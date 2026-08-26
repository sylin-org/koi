# Koi Epic to v1 — canonical continuation ledger

**Status:** active — V1-00 through V1-02 complete; V1-03 through V1-06 in progress; ADR-026/027/028 operator-ratified; **V1-10 webhooks COMPLETE** (embedded parity closed 2026-08-24 per D10; card/SURFACES/profile done); **V1-09 short-lived defaults implemented + physically green both rotations** (diagnosis semantics fixed per D9); **V1-08 principal identity COMPLETE 2026-08-24** — implementation, Tier-2 real-binary lifecycle, and physical mgmt-principal lane green both Linux rotations; **V1-11 step 1 COMPLETE** (Agent-Door spec + executable vector) and **step 2 scaffolded** (TS + Python SDK betas, read-side, tested); owed: SDK enroll-side + publication gating
**Last updated:** 2026-08-25
**Resume phrase:** continue the epic to v1 - lessons ledger at docs/lessons-learned.md (RL-1..RL-16)

**ADR-034 RATIFIED (2026-08-25, operator): multi-channel distribution + free signing.** Research in
`docs/distribution-prior-art.md`; decisions in `docs/adr/034`. Ratified: SignPath Foundation for free
Windows Authenticode (attribution line accepted); macOS terminal-first for 1.0 (notarization deferred);
landing page on the operator's sylin.org Koi page (`install.sh`/`install.ps1` paths, OS-detect,
sha256-verify, invoke `koi install`); npm amended to esbuild-pattern platform carriers
(`@sylin-org/koi-{win32-x64,linux-x64,linux-arm64,darwin-x64,darwin-arm64}` via optionalDependencies —
amends ADR-025's dispatcher shape and its per-target-package rejection; §3 placement rule restated as
law: services never register from npm-managed paths); all top free package managers authorized in order:
Homebrew tap → winget → AUR(-bin) → Scoop bucket → Nix flake (Flathub/Snap/Store deferred with reasons);
tray-minimized autostart via tauri-plugin-autostart with `--minimized` (daemon never spawns GUI).
Implementation phases (each independently landable, external touches operator-gated):
P-C SignPath repository preparation LANDED (`adb4c73`): public CODE_SIGNING_POLICY.md, PE version
metadata via winresource build script, fail-closed `sign-windows` workflow lane (explicit unsigned
status while `SIGNPATH_ENABLED` is false), post-signing checksums/manifest/attestations,
verify-windows-signing.ps1 + checked-in artifact configuration. **Foundation application SUBMITTED
2026-08-25** (project "Koi", repo sylin-org/koi, independent community project, GitHub Actions; account
email on file in local/NOTES.md) — review pending; after approval the operator configures
SignPath/GitHub values and flips `SIGNPATH_ENABLED`.
P-A progress: koi-desktop login autostart + `--minimized` tray launch LANDED (koi-desktop `4f7a38b`,
tauri-plugin-autostart =2.5.1 under the Ghostlight pin policy; Status-pane toggle with honest failure
reporting); landing-page draft LANDED (`site/index.html` + hosting contract in `site/README.md`;
install.sh/install.ps1 already satisfy D2 — checksum-verified, per-user, guidance-not-autostart);
build provenance attestations already shipped in the release workflow. **Tauri updater feed DEFERRED
by operator decision (2026-08-25)** — workbench updates via re-install until revisited; when wanted:
operator generates the Ed25519 keypair (`cargo tauri signer generate`), holds the private key as CI
secret `TAURI_SIGNING_PRIVATE_KEY[+_PASSWORD]`, then pubkey into koi-desktop tauri.conf.json +
`createUpdaterArtifacts: true` + `latest.json` generation in its release flow.
Packaging scaffolds for the P-D channels drafted under `packaging/` (homebrew formula, scoop manifest,
winget manifest notes, AUR PKGBUILD) — deliberately version/hash-placeholdered: they fill at the
stable 1.0 release (prereleases do not belong in these channels; registries immutable per RL-2).
**npm carrier pattern IMPLEMENTED (ADR-034 D5):** `@sylin-org/koi` is now a thin launcher over six
exact-pinned platform carriers (`@sylin-org/koi-{darwin,linux,win32}-{x64,arm64}`); the old
download-dispatcher (bootstrap.js + in-package release manifest) is deleted. Placement law kept:
`koi install` copies the carried binary to the stable per-user location and execs THAT, so services
never register from npm-managed paths; every other subcommand runs the carried binary directly.
`scripts/build-carriers.mjs` assembles carriers in CI from the released bytes — every archive digest
is recomputed against the release manifest before extraction (tamper-tested). Release workflow:
channels job pack-tests entry + all six carriers; publish job (trusted publishing/OIDC) publishes
carriers first, then the entry. 7/7 node tests green; YAML validated.
P-B operator console actions — npm trusted publishers (per package) + `NPM_PUBLISH_ENABLED`;
P-D taps/submissions one by one; P-E optional Apple $99/yr later.

**W5 PARTIAL — announce green, browse-cache defect found (2026-08-26, run `v1-20260826T202817Z-8530fd7f` + diagnostics).**
`windows-mdns` scenario: direction A green (Windows announce API → **avahi-browse on test01 discovers it** —
standards-conformance proof; the Linux koi daemons deliberately skip their own mDNS per ADR-030, so the
honest pairing is Koi vs the OS stacks; avahi tools want the type WITHOUT the `.local` suffix — measured).
Direction B (avahi-publish → Windows browser) exposed a real product defect: **the mDNS browser cache
never populates on Windows** — live events flow (workbench pond unaffected), core reception healthy
(37 packets/12s raw-socket verified, IGMP join fine), but the cache the snapshot API serves stays empty;
reproduced on the standing SYSTEM-context service after hours of runtime. Fix belongs in the browser
worker's cache write path (koi-dashboard browser.rs / mdns-sd Windows reception). Scenario kept as the
regression test; W5 row = partial (announce green, browse ticketed). RL-13 recurrence: test01's
test/test vs the lab password bit once more — per-machine credentials only.
Commits fd89f5f..913a6ab. Remaining W-lanes: W7 (TLS proxy dual-stack), W8 (webhooks), W10 (recovery),
W12 (ACME via W6 DNS), browse-cache fix (new ticket, blocks W5-green), then extended profile + soak.

**W6+W9 GREEN — `windows-breadth` physically proven (2026-08-26, run `v1-20260826T191612Z-b559ca5d`, 4/4 checks).**
Windows-hosted serving lane: DNS authoritative zone served on a lane port picked exclusively-free at
run time (18653+), answered cross-host by brook's dig AND locally by a PowerShell loopback wire probe;
cross-host TCP health both directions (Windows daemon drove brook's 0.0.0.0-bound fixture through
up→down→up via the new `start_cross_host_fixture`; brook daemon watched the Windows HTTP surface).
Operator decision honored: Koi is a zone contributor, never the system resolver — the standard-port 53
serving originally drafted was dropped. Measured workstation facts now recorded in ADR-032 W6: ICS
holds 53 with reuse semantics (bind "succeeds", receives nothing); `Resolve-DnsName` has no `-Port`;
**nslookup sends ZERO packets for non-53 ports** (system DNS client is 53-only) — the PowerShell wire
probe is the Windows-native verifier for lane-scoped ports. Also measured: SO_REUSEADDR bind against a
non-reuse holder fails WSAEACCES 10013 on Windows — cooperative binding is NOT a squatter rescue
(koi-dns keeps the exclusive bind; rationale in code). Fixes landed across the debugging arc: orphan
koi sweep in the runner (the operator called the squatter as our own leftovers — confirmed),
capability-health gate before trusting the lane, dig/nslookup failures carry rule state + local probe
+ daemon log tail (D15). Commits 25b7e42..acad61b. Remaining W-lanes: W5 (mDNS announce/browse),
W7 (TLS proxy dual-stack verification — extend the native-trust windows-client lane), W8 (webhooks
origin-on-Windows), W10 (recovery), W12 (ACME, reuses W6 DNS), then extended profile + soak.

**W4 GREEN — ADR-032 Windows-hosted CA rotation physically proven (2026-08-25, run `v1-20260825T145514Z-c2be3c52`).**
`certmesh-lifecycle-windows-ca` passed 7/7 elevated: wrong-pin refusal before keygen, brook join with
local CSR custody (0600), CA roster membership, renewal with key rotation + roster fingerprint convergence,
revocation pulled to RED self_revocation, refused renewal/rejoin with byte-identical identity, exact
run-owned cleanup. Artifact `b47f1fe0e8d5…` (rc.2 musl), controller tip `b04cefb`. ADR-032 W4 row is now
green both halves (Windows-member half was `certmesh-native-trust-windows-client`, 2026-08-24).
Correction of the prior handoff: the "locks held by v1-…879cc67a" premise was wrong — that id was a stale
hard-coded scenario argument; the real deploy/lock owner then was `v1-…9582ed31`. The physical run exposed
and fixed FIVE first-run defects (all committed 2e7f152..b04cefb): (1) netsh rejects `\\?\` program paths
from `canonicalize()` and reports errors on stdout → strip prefix + surface stdout (`netsh_program_path`,
RL-14); (2) member-side koi CLI calls needed the lane-convention env pinning
(`KOI_DATA_DIR`/`XDG_RUNTIME_DIR={run}/runtime`) — ambient breadcrumb resolution hit the standing service
era (/var/run/koi.endpoint exists post-cutover) and bailed pre-cutover; (3) raw `pkill -f` matched the
transport's own `sh -c` argv and killed the session (exit 128, empty output) → pid-file
`stop_run_daemon`/preserve-state `restart_run_daemon` primitives (RL-15); (4) RED diagnosis + refusal
checks judged exit codes instead of captured content — trust diagnose exits non-zero on RED BY DESIGN
(RL-16, new `remote_output` helper); (5) report now attests secrets_redacted (it only ever carried ids,
hashes, fixed strings). Also: catalog windows address corrected .138→.137 (DHCP lease move measured);
compensating cleanup stops the live CA daemon by exact exe before dir removal; every W4 step is named in
errors (D15 discipline). Standing koi service stopped before / restored after each attempt (RUNNING at
close). Next in W-queue: W5-W9+W12 breadth, W10 recovery, then extended full profile + soak.
**STRATEGY SHIFT (2026-08-24, operator-approved): ADR-031 desktop control plane + ADR-032 Windows 1:1 parity program (GATES STABLE 1.0) + docs/LAUNCH.md.** Stable `1.0.0` now requires: full elevated profile extended with Windows breadth cases (W-matrix in ADR-032), all parity rows green both rotations, clean soak incl. Windows participants. rc.2 soak continues unchanged meanwhile. Next implementation order: (1) ADR-031 config substrate basics (versioned TOML, precedence CLI>env>file>defaults, loud unknown keys, `koi config init`), (2) L0 welcome contract, (3) W1 SCM driver + W2 named-pipe IPC lanes, (4) tray MVP.
**REAL-INSTALL MESH CUTOVER (2026-08-24 late, operator-directed): "no transient
install - everything on the test machines must be real."** The standing mesh now runs
the product's own installer path on all three Linux hosts: `sudo koi install` →
`/usr/local/bin/koi` + enabled `/etc/systemd/system/koi.service` (Type=notify,
Restart=on-failure 5s), default machine data root `/var/lib/koi`, root-owned
breadcrumb `/var/run/koi.endpoint`. Brook re-cut over as CA (CA re-created on the
real service, enrollment open); granite + test-01 enrolled fresh through it
(roster converged 3/3: brook primary + both members active; all diagnoses healthy;
custody 0600). Collector evidence lines appended per host to
`~/koi-dogfood/evidence.jsonl`; scripts committed under `scripts/lab/mesh/`
(mesh-real-install/ca-init/invite-mint/join-real/lan-expose + collector
mesh-status.sh + driver mesh-status-all.ps1). Artifact provenance pinned by
hashing the INNER binary of the published rc.2 GitHub asset:
`006ef30d793fe70c0a7b69c5a71fffcf3b38092f3663508bdaf20a34a27658b8` — verified
byte-identical to what was deployed AND to each installed /usr/local/bin/koi.
(The handoff's earlier `94e7d652…` was the pre-release evidence-series build.)
Deviations: **D16** CA-only LAN exposure via the installer's own documented
mechanism (`systemctl edit koi` drop-in setting `KOI_HTTP_BIND=0.0.0.0`) — real
defaults are loopback-only HTTP (mTLS 5642 is 0.0.0.0 natively); reverse = delete
the drop-in. **D17** old `~/koi-dogfood` trees left in place inert (retire-by-
rename judged needless mutation; rollback = `koi uninstall` + restart old shape).
test-01 additionally had PAM faillock disabled (`deny=0`) by operator decision
after lockouts masqueraded as auth failures; granites' historical 0.7.0
/usr/local/bin/koi artifact preserved by copy before overwrite. Soak clock
restarts at this bring-up (~23:14Z) — the soak now exercises installer-produced
services, which was the point.

**V1-12 progress (2026-08-24 late): config substrate + L0 welcome LANDED (`43a3dc8`).** `koi config init|show|path` shipped; versioned TOML (deny-unknown-keys, loud wrong-version) at platform paths; precedence **CLI > env > file > default** implemented via clap value-source detection and proven LIVE both directions on Windows (file-only port 6001 bound; explicit `--port 5641` overrode it); template restored after probe. L0 welcome banner: three-line contract (LAN name / dashboard URL / next command), marker-gated once-per-data-root, unit-tested. Next under V1-12: tray MVP; then ADR-032 P1 (W1 SCM driver + W2 named-pipe lanes). Launch assets A1-A6 in docs/LAUNCH.md drafted during soak; every external post is operator-executed.

**W4 STATE AT HANDOFF (2026-08-25 ~04:30 local): scenario built, physical run pending.**
The Windows-member half of W4 was already physically green (exercise_windows_member_custody
inside certmesh-native-trust-windows-client, elevated 16-scenario profile 50/50 on
2026-08-24). The remaining half — **Windows-hosted CA rotation** — is IMPLEMENTED and
gate-green but NOT yet physically run: `certmesh-lifecycle-windows-ca` (tools/koi-lab,
commit e0a57aa) runs the CA daemon on this workstation (catalog ports 18541/18542,
HTTP bound to the LAN) behind scenario-scoped firewall rules, with brook as the Linux
member (wrong-pin refusal → 0600 CSR custody join → roster → renewal rotation +
fingerprint convergence → revocation → RED self_revocation → refused renewal/rejoin
with byte-identical identity → exact cleanup incl. firewall removal). Operator
approved the catalog widening: windows mutations now ["scm","firewall"] (1c7efe4).
A fresh musl artifact IS staged and BOTH LAB LOCKS ARE HELD by run
**v1-20260825T125244Z-879cc67a** (deploy succeeded; the scenario then refused on the
not-yet-committed catalog grant — since fixed). Exact next action, elevated:
`cargo run -p koi-lab --locked -- certmesh-lifecycle-windows-ca --run-id
v1-20260825T125244Z-879cc67a --member brook --allow-system-mutation` (verify the
staged artifact version is rc.2 first — an earlier deploy staged a stale rc.1 binary
because deploy reused the old local musl; the fresh build replaced it). On green:
ADR-032 W4 row → green, ledger, cleanup the run (releases locks), push. Fallback:
`.tmp/w4-run.ps1` (untracked scratch) does stop-service→build→restore→deploy(with
run-id propagation)→scenario in one elevated session. Also landed this arc: W2 pipe
test now uses a per-run pipe name (the standing service owns \\.\pipe\koi — the old
fixed name made the test fail whenever a daemon was up), and repo-local `.tmp/`
(gitignored) is the scratch home for UAC one-shots/transcripts per operator policy —
no more %TEMP% litter.

**MESH DISCOVERY FACTS (2026-08-25 early): servers are silent by design.**
Investigating "why does Discover show so few koi peers" revealed the standing
mesh's mDNS topology: **brook and granite do not announce via mDNS and never
did** — Debian 13's systemd-resolved holds 5353, and both servers carry the
operator's own `zen-garden.conf` drop-in (`MulticastDNS=resolve`, Feb 26 — the
ZenGarden/Moss deployment deliberately owns resolved's mDNS). Koi's ADR-030
coexistence skip therefore fires on both at every boot (info-level, truthful
`mdns => disabled`); roster convergence never depended on it (certmesh/mTLS).
`garden-moss` is installed on brook (June, idle — no running process). A
`mesh-mdns-enable.sh` was drafted and TESTED on brook: it works mechanically
(drop-in + restarts) but zen-garden.conf wins drop-in merge order (z > 9), so
enabling koi-announcing on the servers requires an explicit garden-first-vs-
koi-first decision — the script header documents the conflict and the revert.
Verdict recorded: leave the servers silent (garden-first); the workbench pond
shows the Windows peer + the non-koi LAN, servers are found via DNS/certmesh.
Workstation reception note: the rc.2+ service receives continuously (107
events/min-window, "receiving" in status); third-party answer volume is
time-of-day dependent (4 AM LAN is quiet). Also measured: the workstation's
DHCP lease moved .138→.137 (an Android now holds .138 — catalog lab.json still
says .138 for the local node; harmless, local).

**MDNS RECEPTION VERDICT + WORKBENCH TRUTHFULNESS (2026-08-24/25 night).**Physical measurement closed ADR-030's open question on Windows: **elevated
service-mode (SCM/SYSTEM) receives mDNS fully and instantly** — one burst
surfaced 20 service types / 14 devices (Nest Hubs, Brother printer, PS5,
Matter, NAS/Xserve, ZenGarden boxes, Androids) with resolved endpoints — while
the **same binary unelevated receives sparsely** (minute-scale inbound gaps
despite a program-scoped allow rule). ADR-030 amended with the measurement;
skip-trigger redesign deliberately deferred (partial reception > silence).
Daemon-side fix landed: a held-open `/v1/mdns/browser/events` subscription now
re-touches the lazy meta-browse on every heartbeat — "subscribed = browsing" —
with a regression test (the pond used to silently drain 5 minutes after
subscribe; that was the "old page had LOADS, new pane has 5" mystery).
Workbench truthfulness fixes: the Rust readers now PUSH stream state
(`discover-stream` events; "live" is never stale) and `down` is emitted only
when healthz also fails (older daemons without `/v1/events` keep the lamp up,
reconcile covers them). workstation context: the operator installed the old dist koi as a service mid-
investigation; it serves correctly (the "crash loop" this ledger previously
claimed was wrong — probes had caught the service mid-restart). The remaining
entry-count gap was the idle-stop bug running in that pre-fix binary; upgrading
the service to the current build closes it.

**WORKBENCH ARC 2 — event-driven Discover + query burst (2026-08-24 night).**koi-desktop iterated to the operator's delight bar: full Ghostlight stylesheet
adopted verbatim (single delta: Koi accent tokens), lampband nav (Status/About/
Discover), About = the TCG card. **Transport rule (the Ghostlight rule, learned
the hard way): the webview holds no network** — WebView2's stack intermittently
eats loopback fetch/EventSource from the tauri origin, so ALL daemon bytes cross
via Tauri commands (ureq in Rust); live events are pushed to the webview via
emit. Lamp + status ride the daemon's unified `/v1/events` SSE (breadcrumb DAT
auth) — no polling; 60s reconcile is a safety net only. Discover = "inhabitants
of the network": grouped by device, TXT-friendly names, type labels, resolved
endpoints, presence states (live/fading/gone — the workbench remembers past the
daemon's cache eviction), type/state/text filters, update-in-place rows (CSP
lesson: style-src-attr blocks inline styles in injected markup — classes only;
debug sink at %LOCALAPPDATA%\Koi\workbench-debug.log caught it). **New daemon
capability (1:1 doors): `POST /v1/mdns/browser/query` + `koi mdns ping` +
workbench "Ping the pond"** — LazyMetaBrowse::requery restarts the meta+per-type
query burst so every mDNS client answers immediately (idempotent; koi-dashboard
10+5 tests green; full gate green incl. a latent W2 test-binding fix caught by
--all-targets). **W5 finding (physical, this machine):** stale-path firewall
rules left koi.exe unable to receive mDNS resolution responses on the Public
profile — announce-only, never resolved; fixed by adding the product-convention
rule `Koi mDNS (udp 5353)` scoped to the current exe (UAC one-shot). Product
ticket: unelevated `Run once` should surface the daemon's own firewall warning.
Also noted: dozens of stale lab-era firewall rules (udp-*/koi_proxy-*) on this
workstation await operator-approved cleanup.

**DESKTOP PIVOT — koi-desktop workbench (2026-08-24 late, operator-directed).**ADR-033 accepted (koi/docs/adr/033): the desktop surface is a purpose-built Tauri 2
workbench in NEW repo `sylin-org/koi-desktop` (public, Ghostlight-version-pinned:
tauri =2.11.5 / tauri-build =2.6.3), superseding ADR-031's tray-icon L1 before it was
built and resolving ADR-031's deferred L2. Visual system = Ghostlight's stylesheet
VERBATIM with one delta (accent tokens → Koi site blue #60a5fa/#93c5fd); card anatomy
ported from Ghostlight's About view (TCG card: halo/echo/disc/notch/foil, pointer-
driven --mx/--my/--holo); lampband header + tabs; lamp states via body.runtime-*
classes. Scope: the WHOLE capability surface through this UI over the frozen loopback
API (pane map in ADR-033 §5; DNS editor first among editors, ceremony wizard next).
Landed so far: tray (status line/Open/Quit + graceful degradation), Status page
(service strip: Start service / Run once / Stop — run-scoped to its own spawned PID;
honest elevation errors), diagnostic tiles, About card+facts. Daemon stays headless;
CLI/HTTP/workbench are sibling intake adapters. Old web dashboard: deprecated UX per
operator, not embedded, not extended.

**RC PUBLISHED + STANDING MESH LIVE (2026-08-24 evening):** `v1.0.0-rc.2` released after two dry-run gates caught a release-blocking gitignore drop (RL-1) — see docs/lessons-learned.md (11 rules, RL-1..RL-11). Published: GitHub prerelease (6 archives + sha256 + canonical manifest), crates.io koi-* 1.0.0-rc.2 (org CARGO_REGISTRY_TOKEN resolved; July rc.1 was already burned there, hence the rc.2 supersede per RL-2), GHCR image, npm inert by gate. Standing dogfood mesh LIVE on published artifacts: brook `koi-dogfood.service` primary (CA created, enrollment open), granite member joined+healthy (legacy 0.7.0 service stopped/disabled by operator-approved cutover), roster converged 2/2, granite diagnosis healthy w/ 0600 custody. Workstations join cyclically per ADR-029 host classes (scripts in scripts/lab/mesh/). Soak week clock started at mesh bring-up ~19:40Z.
**test-01 joined the standing mesh (2026-08-24 ~19:50Z):** published rc.2 deployed to the CachyOS workstation as a user-level cyclical participant (ADR-029 host class; `mesh-start-user.sh` restarts after reboots, persistent data root preserves membership). Adaptive mDNS (ADR-030) validated in real deployment: avahi holds 5353, Koi logged the coexistence skip at info, status truthfully omits the rung. Enrolled as member via pinned invite with local CSR custody; diagnosis healthy 7/7 checks; roster converged **brook primary + granite member + test-01 member**.
**ADR-032 P1 progress (2026-08-24 night): W2 named-pipe IPC lane GREEN (`named_pipe_ipc.rs`, Windows-gated, runs in CI).** Proves: pipe transport to `\\.\pipe\koi`, mDNS-core bridge, structured error envelopes for resolve-miss AND malformed frames, connection survives bad input. **ADR-030 revised after measurement (RL-7 pattern):** bind-probes cannot identify responders on modern kernels — Chrome/svchost hold 5353 with reuse on stock Windows; exclusive-holder detection would have disabled discovery on every Windows machine. Revised heuristic: Unix skips on avahi-active or exclusive-held; Windows never auto-skips (`--no-mdns` remains operator control). Pipe test initially failed BECAUSE the old skip fired on this workstation - the test caught its own environment assumption, exactly as designed. Remaining P1: W1 SCM supervision scenario (machinery verified present: AutoStart + recovery 5s/10s + non-crash failures + upgrade path); tray MVP queued.
**W1 GREEN (2026-08-24 ~21:52Z): `service-lifecycle-windows` run v1-20260824T214900Z-1c2b7864 passed 10/10 in an operator-approved elevated session.** Proven: run-owned exe installed as SCM service (AutoStart), RUNNING + healthz on standard port 5641, autostart + restart-recovery policy in SCM config, hard-kill -> SCM restarted with a NEW pid -> healthy again, uninstall removed the service, port released, exact cleanup; machine restored (`sc query koi` = 1060). ADR-032 matrix W1 row: green. Remaining to stable gate: tray MVP (V1-12 L1), W2 done, W4-W12 breadth acts, extended full profile + soak incl. Windows participants.
**Physical evidence series 2026-08-24 (artifact musl SHA-256 `94e7d652b7be56844857ac30f918a334fa7c65751773272ca9603845b072181f`, controller commit `184c453`):** every scenario lane green on the post-V1-08..V1-11 tree - certmesh lifecycle/recovery/native-trust both Linux rotations, runtime-reconnect F/R, webhook-fanout F/R, mgmt-principal F/R, capability-story F/R (incl. Act 7 + ACME), service-lifecycle (flagged), bounded-soak 3/3 with restart; exact cleanup everywhere; final preflight preserved Brook not-found and Granite's active/enabled koi 0.7.0 service with fixed artifacts `8b6de1ac...`. The `run-profile full` transaction halted by policy at `certmesh-native-trust-windows-client`, which refused pre-setup because the operator session was unelevated (fail-closed correct); the definitive elevated full profile must run from the scheduled-task context.
**`linux` profile added + first full run green (2026-08-24, controller commit `eda02ca`):** `run-profile linux --allow-system-mutation` = `full` minus exactly the Windows-workstation native-trust case (15 scenarios, 47/47 checks), runnable from an unelevated controller session. First transaction `v1-20260824T142133Z-72cb57bf` passed end-to-end on artifact `94e7d652...`: certmesh lifecycle/recovery/native-trust both Linux rotations, reconnect F/R, webhook F/R, mgmt-principal F/R, capability-story F/R, service-lifecycle; preflight-after-baseline restored. The elevated full profile (with the Windows lane) remains scheduled-task evidence for the release gate.
**Catalog schema v2 + role-matrix planner + test-01 onboarded (2026-08-24, controller commits from `eda02ca`):** `lab.json` is now a four-machine catalog (windows/brook/granite/**test01**) with schema-2 metadata - `roles` (planner participation), `mutations` (per-machine grant for trust-store/systemd lanes), `privilege` (dedicated-box vs workstation), `password_env` (per-machine credential indirection). The `pairings` command prints every valid two-role assignment the planner generates (6 Linux pairings across three hosts; Windows declares caller-side roles only). Mutation grants are ENFORCED in `certmesh-native-trust` (trust-store) and `service-lifecycle` (systemd) independent of the operator flag. Transport now pins `sh -c` regardless of login shell - the first Arch host runs fish, which surfaced as exit-127 on POSIX loops. Preflight surfaces each machine's catalog grants. Adaptive mDNS (ADR-030) implemented + physically validated on test-01 with avahi active: exclusive-bind probe (`koi-mdns::udp_port_exclusively_free`, Unix-exact/Windows-best-effort per doc), compose-layer skip at info (`mDNS capability: skipped - UDP 5353 held...`), status truthful, all non-mDNS lanes alive; unit tests cover free/taken/reuse-holder shapes (libc-gated Unix test). Physical proof: deploy verified the identical musl artifact (`94e7d652...`) on all three Linux hosts, and **mgmt-principal brook(CA) -> test01(principal) passed 5/5** - the first Debian-to-Arch management-plane evidence (raw CSR custody on Arch, client-principal enrollment, MCP initialize over mTLS = 200, revocation to 403 named reason, exact cleanup, Granite koi + test01 avahi baselines preserved).
**Elevated `full` profile COMPLETE - all 16 scenarios green (2026-08-24, run `v1-20260824T145553Z-042f8b3f`):** launched from an operator-approved elevated session via the scheduler script, 50/50 checks passed with redaction attested and preflight-after-baseline restored. This is the first full-profile transaction of the 16-case era (webhook + mgmt-principal lanes included) and the first since the 12-case era greens of 2026-07-20. Windows native-trust client case proved exact LocalMachine\Root identity, Schannel curl + Invoke-WebRequest, hosts restoration, and full trust-store restoration (15/15 checks). Counts toward the release-gate series alongside the linux-profile run at controller commit `eda02ca`.

**D15 - standalone scenario stderr discipline (2026-08-24):** two consecutive standalone `mgmt-principal` invocations failed pre-report while the operator loop discarded stderr; immediate reruns were green in both rotations and the transient cause could not be reconstructed. Corrective rule going forward: standalone scenario invocations always capture stderr to a retained log; a pre-report failure without diagnostics is an instrumentation defect, never an acceptable unknown.


This is the repository's canonical handoff and progress ledger for the v1 epic. The plan is a
working hypothesis, not a frozen specification. Every session must verify it against code, tests,
Git, and the live lab; adjust it when evidence changes the best route, and record the reason.

## Objective

Bring Koi to an evidence-backed v1 by establishing a repeatable three-machine hardware lab across:

- **W:** this Windows workstation (`192.168.1.138` at the last check);
- **L1:** `stone-platinum-brook.internal` (`192.168.1.44`); and
- **L2:** `stone-granite-spring.internal` (`192.168.1.55`).

The lab must exercise Koi's complete public capability surface and its composed whole story, with
certmesh and native OS trust as the first high-value slice. It must prove real Windows↔Linux and
Linux↔Linux behavior, native certificate installation/removal, cross-machine verification,
service lifecycle, clean teardown, and honest failure behavior. Its results become v1 release
evidence rather than a one-off demo.

## User decisions and boundaries

- The user approved this epic and the three-node lab proposal on 2026-07-19.
- The user ratified **"Let everything local find, trust, and talk"** as Koi's banner and
  authorized a full public-documentation realignment around **Find. Trust. Connect.** on
  2026-07-19. ADR-024 is the canonical product-identity decision.
- The user approved an artifact-first release-channel implementation on 2026-07-19.
  ADR-025 is the canonical distribution decision. Preparation and tests are authorized;
  first npm publication, registry/repository creation, package-visibility changes, and
  external WinGet/Homebrew submissions remain separate external actions.
- The user explicitly expects the plan to be naive in places and wants it adjusted as evidence
  accumulates. Do not preserve a bad plan for consistency; preserve the decision trail.
- The privileged lane is approved in principle: it may temporarily modify the Windows
  `LocalMachine\Root` certificate store and Koi service state, and may deploy to/mutate the two
  documented dedicated Linux test boxes. Implement explicit safety gates before exercising that
  authority.
- Every system mutation must be run-scoped, fingerprint/path-specific, preflighted, and reversed.
  Never broadly clear a certificate store, service collection, data directory, or unrelated
  process. A cleanup failure is a failed run with an exact manual remedy.
- The Windows workstation is not a disposable test box. Privileged Windows mutations require an
  explicit runner flag such as `--allow-system-mutation`, an elevated process, pre-state capture,
  and exact restoration.
- On 2026-08-23 the operator ratified **expanding the 1.0 scope** to include, before RC
  publication: principal identity for non-human callers (ADR-026), short-lived leaves as the
  default trust posture (ADR-027), outbound webhook fan-out (ADR-028), an in-tree
  language-neutral trust/Agent-Door spec with conformance vectors (V1-11), and TS/Python SDK
  betas against the frozen HTTP API (V1-11). The mDNS cross-subnet reflector, Terraform
  provider, and Grafana dashboard were consciously deferred to the 1.1 ledger section below.
  Rationale: Koi is unpublished — zero compatibility surface — so differentiating capabilities
  are cheapest *before* the first public artifact; the prepped rc.1 tag is superseded and will
  be re-prepped after V1-08..V1-11 land.
- External publication remains unauthorized. Do not post, contact communities, open external PRs,
  or publish packages. Commit and push also require a separate user request.
- The user explicitly decided that the 6–24-hour soak gates stable `1.0.0`, not
  `1.0.0-rc.1`. Publish an RC early enough to soak the exact distributed artifact; findings become
  `rc.2`, `rc.3`, and so on rather than delaying the first candidate.
- Preserve pre-existing user work. `docs/animations/` was already untracked before this epic.
- On 2026-07-19 the user explicitly authorized the elevated Codex session to continue the V1 epic
  autonomously while they sleep. It may explore, refactor, implement, build locally, exercise the
  documented run-scoped Windows/Linux lab lanes, validate, clean up, and update this ledger without
  waiting for routine confirmations. This does not broaden the mutation boundaries above or grant
  external publication, commit, or push authority. Stop safely when new authority or an ambiguous
  destructive/external action would be required.

## Outcome so far

- Koi's objectives, architecture, capability surfaces, market/ecosystem niche, readiness risks,
  and public claims were mapped. The generated adoption workspace is under `.oss-adoption/` and
  its validator reports `VALID`.
- ADR-024 now defines Koi as an open-source local connectivity substrate that makes containers,
  applications, and devices delightfully discoverable, secure, and interconnected. The README,
  documentation hub and overview, user/container/getting-started guides, `.internal` capability
  card, primary crates.io copy, and generic crate READMEs now use the Find/Trust/Connect model.
  ADR-016 remains the technical strategy and maturity-ordering source, with its public positioning
  explicitly refined by ADR-024. Historical ADRs, changelog/assessment artifacts, and the
  user-owned `docs/animations/` tree were deliberately preserved.
- ADR-025 defines one native build and one deterministic release manifest as the publication
  chokepoint. The release workflow now validates all six archives and checksum sidecars, attests
  and publishes the manifest, and exercises the dependency-free npm bootstrap during dry runs.
  `cargo-binstall` metadata consumes only official Koi archives with unofficial-binary and compile
  fallbacks disabled. `@sylin/koi` is implemented as a version-pinned installer dispatcher, never
  a cache-hosted runtime; npm publication is inert until trusted publishing and the explicit
  `NPM_PUBLISH_ENABLED` repository variable are configured. Release prep now stages only known
  release files, and tagging defaults to the exact remote `main` tip. Validation is green:
  manifest/bootstrap tests (7/7), zero-dependency npm audit and real-v0.9.0 pack smoke, actual
  six-archive manifest generation, Cargo package/metadata validation, POSIX and Windows PowerShell
  parsing, actionlint, formatting, and the complete locked workspace test/doc-test suite. Hosted
  Release dry run [#43](https://github.com/sylin-org/koi/actions/runs/29698199626) then passed on
  commit `330cda3`: workspace test, all six native build/package/checksum/upload lanes, canonical
  manifest validation, npm tests, and npm pack. Tag-only release, GHCR, crates.io, and npm jobs
  were skipped as designed, so the run published nothing.
- The `1.0.0-rc.1` channel blocker is removed locally. `scripts/release-version.mjs` is now the
  single evaluator for SemVer identity, tag, prerelease status, and npm dist-tag across version
  preparation, tagging, manifests, and workflows. Tag/workspace disagreement fails before
  publication. RCs become GitHub prereleases, exact-only GHCR tags, npm `next`, and exact-version
  crates.io publications; stable releases alone advance public defaults. The combined stable/RC/
  malformed-version/manifest/bootstrap/channel-wiring suite passes 13/13, PowerShell and workflow
  YAML parse, npm's staged-manifest pack passes, Cargo metadata and the 17-crate publish inventory
  agree, surface lint reports 26 honest rows, formatting passes, and `koi-lab` remains 45/45.
- The existing whole-story design, ADR-018 tiers, surface ledger, QA workflow, physical-host
  runbook, deployment script, Linux↔Linux hardware harness, Windows↔Linux-container harness,
  certmesh/trust implementation, and external `os-truststore` behavior were inspected.
- Both physical lab hosts were verified live through read-only SSH on 2026-07-19:
  - brook reported `stone-platinum-brook`, Linux `6.12.69+deb13-amd64`;
  - granite reported `stone-granite-spring`, Linux `6.12.90+deb13.1-amd64`.
- Local prerequisites exist: PuTTY `plink`/`pscp`, OpenSSH, `cross 0.2.5`, and Docker client/server
  `29.5.3`.
- V1-00 exploration was completed on 2026-07-19 under the repository's mandatory `explore`
  workflow. A fresh `cargo build --release --locked` passed, the unchanged Windows integration
  harness reproduced **123/131 passed, 8 failed, 2 skipped**, and the unchanged concurrency
  harness passed 50 registrations / heartbeats / removals. The integration run cleaned up its
  process and temp directory; only a normal `TIME_WAIT` socket remained.
- Both lab hosts were re-verified with operator-authorized dedicated test credentials supplied
  out of band and pinned PuTTY host keys. Their fixed Koi binaries and pre-existing service state
  were captured as baseline and left unchanged by every completed run.
- V1-00 was implemented and validated on 2026-07-19. The repaired Windows QA harness passed
  **128/128 assertions with 2 environmental skips**; concurrency passed 50 registrations,
  heartbeats, and removals. The full locked Rust suite, all-feature clippy with warnings denied,
  formatting, audit, and native release build passed.
- A static `x86_64-unknown-linux-musl` release was cross-built **on the Windows workstation via
  Docker**, never on a test server. Artifact SHA-256:
  `7C54C0296128ADEB0E009CA460149F32D97154A90E97F2B37948E6987875202A` (40,944,656 bytes).
  That artifact passed the local two-container bridge-network certmesh scenario
  (create→invite→join→roster→revoke→rejoin refused). The script removed its containers/network
  and staged file afterward.
- V1-01 was implemented as the non-published `tools/koi-lab` workspace tool. It centralizes the
  declarative node inventory, pinned SSH identities, preflight, local cross-build, artifact
  identity, distributed lock, run-owned deployment, exact cleanup plan, cleanup execution, and
  redacted JSON evidence. `scripts/integration/deploy.ps1` is now only a compatibility wrapper;
  it refuses the old persistent setup behavior.
- The controller deployed the same Koi 0.9.0 musl artifact to isolated run directories on brook
  and granite, verified the native SHA/version, and refused a concurrent deployment with the
  recorded lock owner. Cleanup removed only its allowlisted run-owned files and locks.
- The first three-machine vertical slice passed on run
  `v1-20260719T055642Z-eb8eadcb`: brook created the CA, granite joined as a member, Windows drove
  both high-port health checks, the invite pin matched the CA, the roster contained granite, and
  granite diagnosed `Healthy / Authenticated`. Linux system trust-store fingerprints were
  unchanged before/after. Exact cleanup stopped only run-owned binaries and removed both run
  roots and locks.
- Post-cleanup preflight proved the original fixed binaries still have SHA-256
  `8b6de1ac7f478a376021906b662f5809fa4f4e67ebdeb58394cec5b90a1dc263`; brook remains without an
  active Koi service, while granite's pre-existing `/usr/local/bin/koi --daemon` service remains
  active on port 5641. The current Windows process is not elevated, so no Windows trust-store
  mutation has been attempted.
- Full workspace validation after V1-01 passed: formatting, all-target/all-feature clippy with
  warnings denied, the complete locked test suite, audit, native release build, publish-list
  coverage, the surface-ledger linter, and diff hygiene are green. The validation run exposed and
  fixed a real TOTP isolation defect: all slot tables had shared one machine-global credential
  label. Slot-table v2 now derives stable per-slot labels at the crypto boundary, retains the v1
  legacy read path, and has a two-slot isolation tripwire. The surface linter was also made CRLF
  safe for Git Bash without changing its ledger contract.
- V1-02 now has one privileged Linux mutation boundary. The controller refuses without
  `--allow-system-mutation`, requires run/lock ownership and passwordless sudo, uses exact
  run-owned CA/state paths, and compensates post-install failures through the same removal path.
  Windows remains the control-plane driver; its LocalMachine store has not been touched.
- A current static musl artifact was rebuilt locally through Docker/cross (never remotely):
  40,944,480 bytes, SHA-256
  `c3de84f63e43f9bb9277755395319952ad2c434794dfc4b945c00705341d956e`.
- Privileged run `v1-20260719T063001Z-0d96f847` passed the first native trust rotation. Brook
  rejected granite's real Koi TLS proxy before root installation; after exact root installation,
  native `curl` and OpenSSL verified it without a custom CA; wrong-host verification failed; Koi's
  tracked fingerprint matched; exact removal made TLS fail again; and brook's complete trust-store
  fingerprint returned to its captured baseline. The report is secret-redacted.
- The run exposed an `os-truststore 0.0.2` Debian cleanup defect: uninstall removed the anchor but
  left two dangling `update-ca-certificates` symlinks. The lab boundary now prunes them only after
  verifying the missing exact anchor, full symlink target, and fingerprint marker. This is an
  explicit compatibility workaround and upstream debt, not hidden success.
- Final cleanup removed both run roots and distributed locks. Post-cleanup preflight again shows
  the fixed 0.7.0 binaries at their original hash, brook's Koi service inactive/not-found, and
  granite's pre-existing PID 803 service active/enabled on 5641.
- Post-V1-02 validation is green: formatting, all-target/all-feature clippy with warnings denied,
  the complete locked workspace and doc-test suite, native release build, and audit all pass. Audit
  retains only the already-dispositioned `anyhow 1.0.102` advisory and yanked transitive
  `spin 0.9.8` warnings.
- The next V1-02 slice centralized certificate names in certmesh. `CoreSpec.dns_config.zone` now
  enters the immutable `IssuanceNames` policy once; member CSR creation, CA authorization,
  installation state, self-enrollment and renewal all derive hostname + configured-zone FQDN at
  that chokepoint. The CLI no longer synthesizes `.local`. Existing roster/member state gains the
  configured-zone SAN on renewal while retaining legitimate historical SANs; a CA self-leaf that
  lacks its configured name reissues even when it is otherwise not due. Koi DNS's standalone and
  embedded default is now consistently `.internal`.
- `koi-lab` now has one role-driven trust transaction with `linux-forward`, `linux-reverse`, and
  `windows-client` assignments. Builds produce Windows and static-musl artifacts locally only.
  The Windows adapter targets `LocalMachine\Root`, compares the exact SHA-256 certificate identity,
  drives Schannel through `curl.exe` and `Invoke-WebRequest`, restores the exact original hosts-file
  bytes in a `finally` block, and compensates through the tracked removal path. An unelevated proof
  with the mutation permit present refused before run lookup, remote contact, local setup, or store
  mutation.
- Local artifacts for this slice: Windows 35,363,328 bytes, SHA-256
  `9f3edc8f2958078010c4f9a7068ff7ccf0d9e2ef76d808ff0c5b01cd3d0324a0`; Linux musl
  40,995,464 bytes, SHA-256
  `57c0ef1ed44ad8a31284431b3a80fd7012aace48473d7940d9319473adcead2a`.
- Privileged reverse run `v1-20260719T192531Z-a1d121c9` passed: Granite CA/native client → Brook
  member/proxy proved fail-before, exact install, native curl + OpenSSL, wrong-host rejection,
  tracked fingerprint `4aaac27d48df48d69ac2d45605f0c119559f51c08c3083941316ac842ccf4634`, exact removal,
  fail-after, and full Granite trust-store restoration. Exact cleanup removed both run roots and
  locks; post-cleanup preflight preserved Granite's pre-existing PID 803 Koi 0.7.0 service and both
  fixed artifacts.
- The first reverse attempt correctly failed its final store-baseline check and exposed a second
  Debian compatibility shape: OpenSSL assigned a fingerprint-owned `.1` hash link, while cleanup
  scanned only `.0`. After verifying run ownership, the full CA SHA-256, missing exact anchor, and
  exact dangling target, only `/etc/ssl/certs/0a39125c.1` was removed. The guarded cleanup now scans
  every numeric hash suffix and the fresh reverse run proved full restoration.
- Current-slice validation is green: formatting, all-target/all-feature Clippy with warnings denied,
  the complete locked all-feature workspace + doc-test suite, 332 certmesh tests plus one ignored
  generator, 20 lab tests, 81 embedded unit tests plus its integration/doc suites, both local release
  builds, the 17-crate publish inventory, the 22-row surface ledger, the unelevated Windows refusal
  proof, and physical Linux trust, lifecycle, cold recovery, and breadth Acts
  0/3/4/5/6/7/8/10/11 plus ACME in both directions with exact cleanup. `cargo audit` exits green
  with only the two already-dispositioned allowed upstream warnings (`anyhow`, `spin`).
- V1-03 now has one role-driven `certmesh-lifecycle` scenario. The member first rejects a deliberately
  wrong invite fingerprint before generating a key, then proves private-key and state mode `0600`,
  leaf/key correspondence, full CA chaining, hostname plus configured `.internal` SANs, explicit
  operator renewal with key rotation, CA-roster convergence, exact daemon restart with identity and
  proxy persistence, revocation pull and RED diagnosis, and CA refusal of a revoked member's renewal
  without replacing the working identity. It also records the honest boundary that an unexpired
  revoked leaf remains acceptable to generic TLS clients while Koi has no CRL/OCSP distribution.
- The first lifecycle attempt (`v1-20260719T201634Z-452ff7c9`) exposed a real non-default-port defect:
  enrollment persisted the hard-coded mTLS port 5642 even though the role CA listened on 16542.
  The install protocol now carries an optional `ca_mtls_port`; the CLI exposes
  `certmesh join --ca-mtls-port`, validates zero before any write, and persists the chosen endpoint.
  The lab supplies the declarative CA role's port instead of patching member state after enrollment.
- Fresh artifact SHA-256 values after that fix are
  `c8e8ba8e7de9916e6d9dc7e976909873ad3e8dc45cf075f1f2258bf15bc0d764` for the locally
  cross-built Linux-musl binary (41,327,440 bytes) and
  `778e02c816056a5a9a3ee9452490177162ddb0466136a7478532badceb2a0027` for the native
  Windows binary (35,650,560 bytes).
- Both physical Linux lifecycle directions passed with that exact artifact: forward run
  `v1-20260719T203100Z-9f60f0ec` used Brook as CA and Granite as member; reverse run
  `v1-20260719T203319Z-2976add5` used Granite as CA and Brook as member. Ownership-checked cleanup
  removed both run roots and locks. Final preflight proved Brook's fixed 0.7.0 artifact/service
  baseline and Granite's pre-existing enabled PID 803 service on port 5641 were unchanged.
- Backup/recovery exploration exposed a public-contract gap: restore wrote CA material but did not
  bind clone protection to the recovery host, create a usable local CA leaf, or publish secure
  posture; self-enrollment could also reuse a fresh-looking leaf without proving its CA chain and
  private-key correspondence. Restore now prevalidates the full decrypted payload and CA key/cert
  pair before its first write, clears member-only/ephemeral state, records the current machine
  binding, and self-enrolls through the normal posture chokepoint. Identity diagnosis and leaf
  reuse share one chain-plus-key-material integrity evaluation.
- `koi-lab certmesh-recovery` now proves cold recovery rather than merely checking
  `restored=true`. Its request bodies stream over stdin so passphrases and encrypted bundles are
  absent from process arguments and evidence. It verifies wrong-pass immutability, exact run-owned
  data loss, an uninitialized replacement, CA fingerprint/roster recovery, mode-0600 host binding,
  restored-mTLS key rotation, locked restart without member mutation, old-pass rejection, new-pass
  unlock, a second renewal, and the restored audit event.
- Both physical recovery directions passed using Linux-musl artifact
  `5259ec5bfc7751ca24ed191f44154d05ef51fc724c03e39044d03434f453ea5f`
  (41,421,736 bytes): forward run `v1-20260719T210602Z-a8f6689f` recovered Brook; reverse run
  `v1-20260719T210709Z-fa395b82` recovered Granite. The matching native Windows artifact is
  `07f7aa473a6164a28ed013eda31b58e2ce674c663c67f28e95dbffdec8ce842c`
  (35,706,880 bytes). Exact cleanup and final preflight again preserved both fixed 0.7.0 artifacts
  and Granite's enabled PID 803 service.
- V1-04 breadth has one role-driven `capability-story` transaction. Its centralized daemon profile
  enables explicit high-port DNS, mDNS, health, proxy, UDP, Docker runtime, dashboard, MCP, Unix
  IPC, and the posture-reactive ACME listener. Run-owned fixture, container, and image
  lifecycles verify executable or Docker identity plus the exact run owner before termination; the
  same cleanup path removes their residue as well as daemon/data/runtime state.
- Physical Acts 0, 3, 4, 6, 8, and 10 passed in both Linux directions. Forward run
  `v1-20260719T215827Z-e3c92339` used Brook as primary and Granite as observer; reverse run
  `v1-20260719T215958Z-3c31ad8d` swapped them. Both proved isolated mode-0600 breadcrumbs and
  Unix sockets; HTTP plus real cross-host `dig`; multicast resolve/heartbeat/goodbye removal;
  health Up→Down→Up; protected UDP SSE; and live status, dashboard events/snapshot, host,
  OpenAPI, Prometheus, authenticated MCP resources, public server-card, and Unix IPC. Exact
  cleanup removed both runs. The exercised Linux artifact remained
  `5259ec5bfc7751ca24ed191f44154d05ef51fc724c03e39044d03434f453ea5f`
  (41,421,736 bytes).
- Hardware exploration corrected three stale harness/spec assumptions without weakening the
  product contract: DNS entry names are canonical trailing-dot FQDNs; non-meta mDNS intentionally
  coalesces `ServiceFound` into the richer Resolved event; and UDP status is a DAT-protected read.
  A fourth stale assertion expected dashboard detail under a wrapper even though the shared
  snapshot deliberately flattens the centralized capability ladder and domain detail.
- Acts 5 and 11 now extend that same story driver rather than adding a scenario. The controller
  copies back the exact deployed static binary, builds a `FROM scratch` image locally, transfers
  it under a run-only tag, and never builds or pulls on the Linux nodes. One labeled Docker start
  must appear in runtime inventory and derive mDNS, `.internal` DNS, HTTP health, and a live
  self-signed TLS proxy; stop must remove every derived resource, the container, and the image.
  Forward run `v1-20260719T225959Z-307ab6a5` used Brook as primary; reverse run
  `v1-20260719T230234Z-0f8efc9a` used Granite. Both passed Acts 0, 3, 4, 5, 6, 8, 10, and 11 with
  Linux artifact `f0eb5dc3213c6a5af8ebe81d8c0254bcef988beaab6455fe03c78dc3211f62e8`
  (41,409,728 bytes). The matching Windows artifact is
  `660b8c01a76d7f07d033a9c5d59f35cd726c425bd42121b1a4307ceaee649513`
  (35,717,632 bytes). Final preflight `preflight-20260719T230458Z.json` preserved Brook's inactive
  service and Granite's original enabled PID 803 service; no run locks, containers, or images remain.
- Physical orchestration exposed one real responsibility split: `ProxyCore::upsert/remove` persisted
  configuration but non-HTTP producers could not reconcile listeners. `ProxyRuntime::upsert/remove`
  now owns persist-plus-apply, and both HTTP and the runtime orchestrator use that chokepoint. The
  live cross-host TLS proxy round-trip proves the listener is not merely configured. A later 200
  from mDNS resolve was correctly traced to the harness checking before its removal-event barrier;
  cache invalidation was already centralized, so no speculative mDNS product change was made.
- Act 7 and the ACME mini-act now extend that same transaction rather than introducing another
  scenario. One shared certmesh provisioning chokepoint owns pinned enrollment and wrong-pin
  refusal. The service receives a certmesh-sourced `.internal` proxy; the controller proves native
  fail-before, exact root installation, hostname success/wrong-host rejection, key-and-certificate
  rotation, a changed physical leaf without daemon restart, exact trust-store restoration, and
  fail-after-removal. A real `instant-acme` client publishes dns-01 proof through Koi's authenticated
  ephemeral-TXT API, the other host observes it with `dig`, the server validates through
  `AcmeDnsBridge → DnsCore`, exact cleanup removes only that value, and the issued chain/SAN verify.
  Final-tree forward run `v1-20260720T005439Z-b45c65a3` and reverse run
  `v1-20260720T005742Z-fd4fd625` passed all Acts 0/3/4/5/6/7/8/10/11 plus ACME. They used the
  locally built Linux artifact `e066766e63387ce82533637781cc3e2dab4a74c65a2c33081812a011f926e93a`
  (41,504,512 bytes); matching Windows artifact
  `a56dc43dda0bc16edb73689b40d19c7d042c1338fe73c1b69cb026c3f2b98277`
  (35,719,168 bytes). Final preflight `preflight-20260720T010104Z.json` preserved Granite's original enabled PID 803 service, Brook's
  inactive service, both fixed 0.7.0 artifacts, and left no run locks, high-port processes, or images.
- The first reusable Tier-1 breadth slice is now always-on in `koi-compose`. `RuntimeCore::ingest_event`
  is the one state-update-and-fan-out path shared by real backends and custom/synthetic producers.
  A normalized start event must populate runtime inventory and derive mDNS, DNS, health, and a live
  self-signed proxy; the matching stop must reverse all five. This closes the synthetic
  runtime/orchestrator seam without adding a fake backend or a parallel policy engine. Broader
  multi-instance HTTP/dashboard/MCP composition remains under V1-04.
- V1-05 startup reconciliation exposed a real subscription race: `RuntimeCore::start_watching`
  could inventory already-running containers and broadcast their start events before the
  orchestrator subscribed. `spawn_orchestrator` now subscribes first, then reconciles the current
  runtime inventory through the existing `handle_start` chokepoint before consuming queued/live
  events. The always-on composed regression deliberately starts the orchestrator after an instance
  already exists and proves full derivation plus reversal. Physical forward run
  `v1-20260720T014815Z-96794673` kept container `006b7f62ac9d…` running while Brook restarted
  (`38290` → `38620`); reverse run `v1-20260720T015153Z-558233f4` kept container
  `345e5ec548b2…` running while Granite restarted (`67926` → `68309`). Both reconstructed runtime
  inventory, mDNS, `.internal` DNS, health, proxy configuration, and a real cross-host proxy body,
  then reversed them exactly on container stop. Both used locally built musl artifact
  `928522b3c18fce60a28310e619fbb4ff715d8b0a9f03c059842eaef6629f8d07` (41,518,032 bytes); the
  matching Windows artifact is `8f0f28131c759ea2d05c3b4644e3d622545487d32f52779cad98327ee2151565`
  (35,739,136 bytes). Final preflight `preflight-20260720T015538Z.json` preserved Granite's original
  enabled PID 803 service, Brook's inactive service, both fixed 0.7.0 artifacts, and left no run
  locks, high-port processes, containers, or images. Docker event-stream disconnect/reconnect is a
  separate remaining resilience lane.
- The elevated Windows lane is now physically green. The first successful native-trust run,
  `v1-20260720T024454Z-41226563`, proved exact `LocalMachine\Root` SHA-256 identity
  `9a88063790efd2c7a78bd1d622ace2a5d4bf3231c3942ec5ef34f5787e42bcf8`, Schannel
  `curl.exe`, `Invoke-WebRequest`, wrong-host rejection, fail-after-removal, byte-exact hosts-file
  restoration, and complete trust-store restoration. It also exposed two useful integration facts:
  Windows PowerShell's `Cert:` provider is not guaranteed in this host configuration, so store
  inspection now uses provider-independent read-only `.NET X509Store`; and Schannel needs
  `--ssl-revoke-best-effort` for a private CA with no CRL distribution point. CA and hostname
  verification remain enabled; `-k`, `--insecure`, and `--ssl-no-revoke` are forbidden by a test.
  Exact cleanup finished and preflight `preflight-20260720T024640Z.json` matched baseline.
- The smallest safe V1-03 Windows custody slice then passed inside the already tracked native-trust
  transaction. Run `v1-20260720T030254Z-bb6572bc` used Brook as CA, Granite as service, and a
  run-owned loopback Windows member on ports 18541–18555. Windows rejected a deliberately wrong pin
  before creating a key, joined with local key custody, diagnosed Healthy, appeared Active in
  Brook's roster, and proved SID-based ACLs on the protected data root, member key, member state,
  and protected DAT breadcrumb: only SYSTEM, BUILTIN\Administrators, and the current user had allow
  ACEs. The same transaction proved exact LocalMachine root identity
  `5cb069719615e570e7590cfd30a8fe4ad5ec55559d77c7aac24928d1abb3fb86`, both native clients,
  wrong-host/fail-after rejection, exact hosts bytes, and full-store restoration. Its exact spawned
  child and owner-marked local directory were removed before success; owner-checked remote cleanup
  removed only that run. Final preflight `preflight-20260720T030419Z.json` showed no lab listeners,
  roots, locks, or run processes; Brook remained inactive and Granite's original enabled Koi 0.7.0
  service remained PID 803. Both locally built artifacts retained SHA-256
  `928522b3c18fce60a28310e619fbb4ff715d8b0a9f03c059842eaef6629f8d07` (Linux, 41,518,032
  bytes) and `8f0f28131c759ea2d05c3b4644e3d622545487d32f52779cad98327ee2151565` (Windows,
  35,739,136 bytes).
- The remaining elevated Windows V1-03 member lifecycle passed on 2026-07-20 inside that same
  tracked trust transaction. The first two exact-cleanup attempts exposed real defects rather than
  product failures: `v1-20260720T041817Z-3c30c620` found Schannel rejection at the local proxy, and
  `v1-20260720T042416Z-cf6a51fb` localized it to a freshly issued leaf whose `notBefore` was a few
  seconds ahead of Windows. Certmesh now backdates CA and leaf validity by its one 300-second clock
  skew policy without shortening expiry. Member CSR generation also stages `key.pending.pem` and
  promotes it only after the returned leaf matches the key and pinned CA, so a revoked/failed
  rejoin cannot replace the active identity. The first failed run retained its redacted smoke
  report; the diagnostic controller then retained `windows-member-failure.json` for the second.
  Both were owner-cleaned exactly.
- Green run `v1-20260720T043212Z-0b37baee` used Brook as CA, Granite as service, and the run-owned
  Windows member. Key hash `6b2e19a825fc4e92…` rotated to `15cc14f07b399e07…`; cert hash
  `242296e4a1cb2d2d…` rotated to `f476482bb4f87205…`; CA roster fingerprint
  `76f4780218d52088ded4847b6f505057ddf5bf5e291350d8f5159477c68569c3` matched. The exact child
  restarted PID `41980→19832` with byte-identical identity, Healthy diagnosis, and Schannel proxy
  continuity, then PID `19832→23936` pulled revocation and diagnosed RED/self-revoked. Renewal and
  fresh-invite rejoin were refused and left both active files byte-identical. Exact LocalMachine
  root `c4de1f63a0c115ab689bccbaf84505e368e158807b19cb863e54102f6cbf64d0` was removed and the full
  baseline restored. Artifacts: Linux
  `8178b6cd00fe9996bc6f2be748593124e6c9f4ba5569bb9042899fcaf20ed011` (41,506,592 bytes), Windows
  `45036ca7adc119dbda80918a5fb212845db8b41684d048c0a1fae0bde279cc7a` (35,726,336 bytes). Final
  preflight `preflight-20260720T043333Z.json` and independent fingerprint/hosts/PID/port/path checks
  found zero residue; Brook remained inactive and Granite's original enabled PID 803 service was
  unchanged. Windows cold recovery remains unclaimed.
- Portable Tier-1 aggregation breadth now reuses the existing real-binary two-daemon harness. Both
  concurrent isolated instances prove `/v1/status`, `/v1/host`, the centralized dashboard ladder,
  public enabled MCP card, tokenless MCP 401, all 11 authenticated tools, all four resources, and a
  live resource read. Both tests in `two_daemon_certmesh` pass, including the existing certmesh
  enrollment/revocation story.
- Guarded Docker event-stream reconnect is implemented without a host-daemon fault. The backend
  preserves inventory on disconnect, flips runtime health at the single ingest chokepoint, retries
  with bounded 250 ms→5 s backoff, pings and relists, and emits only material stopped/started/updated
  deltas through normal lifecycle policy. Full normalized snapshots and deterministic port/IP
  ordering make the relist comparison exact; `discovered_at` changes, duplicate engine events, and
  inclusive cursor replay produce no lifecycle event for an unchanged instance. Reconnected is
  marked only after reconciliation. The orchestrator contains no parallel reconnect engine.
  `koi-runtime` 49/0 and `koi-compose` 14/0 pass. The physical lane now uses a mode-`0600`,
  run-owned Unix relay as the daemon's process-scoped `DOCKER_HOST`, so a fault closes only Koi's
  connection and never restarts Docker. Forward run `v1-20260720T181705Z-f96627ae` and reverse run
  `v1-20260720T181902Z-165ff7be` each proved health false/true, preserved last-good inventory and
  unchanged operational state, stable mDNS registration (`07e03545` / `269ddfcf`), live derived
  DNS/health/proxy/mDNS behavior throughout, exactly one stopped/started/updated delta, no unchanged
  or cursor-replay lifecycle event, and exact relay/container/image/network cleanup. Both used the
  clean locally built musl artifact
  `0d5d47d850d52c601a70941b525a80a1dabac0dd861e95dfbca6ee9c2c42f4f7` (41,566,120 bytes).
- DNS capability loss/recovery is now truthful at the shared lifecycle chokepoint. `DomainRuntime`
  awaits a fallible asynchronous launcher before marking a loop running and generation-checks
  completion, so a failed bind stays stopped/retryable and an older loop cannot mark its replacement
  stopped. `DnsRuntime` binds both sockets before `/v1/dns/serve` reports success. The existing
  physical Act 3 now preserves a record across stop, observes centralized `stopped` status, installs
  an exact run-owned UDP conflict, requires HTTP 500 on restart, removes the conflict, retries, and
  proves the same answer with cross-host `dig`. Forward `v1-20260720T190754Z-fdc848da` (Brook PID
  `57914` → `58297`) and reverse `v1-20260720T191154Z-adb441bc` (Granite PID `111400` → `111831`)
  passed the complete story with clean commit `27b268d` and musl SHA-256
  `199a4b46faa3ef5777b949ffd46684f468e279324f4f98c9e9f1369a856f3287` (41,511,128 bytes).
- Linux systemd supervision is now a reversible physical V1-05 lane. `koi-lab service-lifecycle`
  creates only a run-named transient unit on Brook, verifies `Type=notify`, transient fragment/user/
  executable identity, and SIGKILLs only its exact MainPID. Green run
  `v1-20260720T194505Z-4b9b9788` replaced PID `64274` with `64608` (`NRestarts=1`), rotated the DAT,
  and reconstructed runtime inventory, DNS, cross-host mDNS, health, TLS proxy state, and live proxy
  traffic. Shared `derived.rs` is now the single complete-derived-service evaluator used by both
  runtime reconnect and service restart scenarios. The run used clean controller/artifact commit
  `cc3685d` and the same locally built musl SHA-256
  `199a4b46faa3ef5777b949ffd46684f468e279324f4f98c9e9f1369a856f3287`. Exact service cleanup left
  Brook without a permanent Koi unit/binary/data root; full cleanup removed both run roots/locks;
  final preflight `preflight-20260720T194652Z.json` preserved Granite's active/enabled PID 803.
  Public fixed-path Linux install/uninstall remains unclaimed.
- A bounded physical soak profile now reuses the shared complete-derived-service evaluator rather
  than inventing parallel assertions. Each iteration uniquely starts a container, converges runtime/
  DNS/cross-host-mDNS/health/TLS-proxy/live traffic, removes it, and requires every projection absent.
  Selected iterations restart the daemon with the container live and require PID/DAT rotation plus
  full reconstruction. Bounds are 1–100,000 iterations and 1–1,440 minutes; duration gates admission
  of the next individually timed-out iteration. Short proof `v1-20260720T195910Z-a235c0c4` passed
  3/3 in 29,614 ms; iteration 2 restarted Brook `66702→67236`. It used clean commit `8907a15` and
  musl SHA-256 `199a4b46faa3ef5777b949ffd46684f468e279324f4f98c9e9f1369a856f3287`.
  Exact cleanup and final preflight `preflight-20260720T200046Z.json` left no run roots/locks and
  preserved Granite PID 803. A scheduled 6–24 hour release soak remains unclaimed.
- V1-06 now has one evidence-publication chokepoint. Every completed check-bearing `koi-lab`
  scenario report declares its checks and redaction verdict once, then renders all formats before
  writing canonical JSON, JUnit XML, and a readable text summary. Publication refuses a report
  that has not explicitly attested secret redaction. Physical run
  `v1-20260720T202701Z-5db023d1` at clean commit `f435382` produced all three certmesh-smoke
  companions and parsed as 6 tests / 0 failures. Exact cleanup and final preflight
  `preflight-20260720T202852Z.json` preserved Granite PID 803 and left Brook inactive. The final
  workspace gate also exposed and fixed a Windows-only DNS test assumption: TCP now chooses the
  collision port, which proves partial UDP-bind cleanup and avoids UDP/TCP excluded-range drift.
- V1-06 unattended policy orchestration is implemented at `c37fdb6`. Smoke, certmesh, full, and
  soak are centralized case lists over existing scenario evaluators. Every case receives a fresh
  deploy/scenario/cleanup transaction; failures stop admission after cleanup, aggregate evidence
  contains only stable phase/status text, and final preflight compares stable host/service/artifact/
  socket baselines while excluding clocks. Physical smoke execution
  `v1-20260720T205716Z-41637b4e` passed 8/8 in 63 seconds across forward child run
  `v1-20260720T205733Z-2a4cc973` and reverse child run
  `v1-20260720T205756Z-939cba58`. Parsed JUnit reported 8 tests / 0 failures. Both exact cleanups
  succeeded, Brook returned inactive, and Granite's original active/enabled PID 803 service retained
  the same executable/start time.
- The elevated certmesh policy then passed execution `v1-20260720T211240Z-df893184`: all seven
  fresh transactions passed deploy/scenario/cleanup, aggregate JUnit was 23/23, both Linux role
  rotations restored their complete trust stores, and the Windows rotation restored hosts and
  `LocalMachine\Root`; an independent SHA-256 lookup found zero copies of its run CA afterward.
  The full policy passed execution `v1-20260720T211813Z-47d0f395` in 12m57s: all 12 fresh
  transactions passed deploy/scenario/cleanup and aggregate JUnit was 38/38. It includes the same
  seven certmesh cases, both Docker-reconnect rotations, both capability-story/ACME rotations, and
  Brook systemd supervision (`92889→93222`, one restart). Final preflight left Brook inactive,
  preserved Granite's active/enabled PID 803 with the same executable/start time, and matched the
  stable listener/artifact/service baseline. This is consecutive full green **1 of 3**.
- The thin Windows scheduling adapter is implemented in
  `scripts/lab/scheduled-profile.ps1`. It only builds locally and calls the centralized
  `run-profile full`; it owns no scenario membership, assertions, deploy, cleanup, baseline, or
  evidence policy. `-Install` securely prompts once, stores only a CurrentUser-DPAPI ciphertext
  outside the repository, and registers one highest-privilege interactive-token task for Monday
  03:00 local time by default. `-Run` refuses a dirty worktree before build, secret decryption, or
  lab mutation; `-Remove` unregisters the exact task and credential while retaining logs/evidence.
  Parser, plan/default override, invalid-schedule/non-admin refusal, a synthetic CurrentUser-DPAPI
  round trip, secret-literal scan, diff hygiene, formatting, and all 37 focused `koi-lab` tests are
  green. The proposed Windows CI plan tripwire was omitted because the current GitHub token cannot
  update workflows; no nonexistent CI guard is claimed. The first elevated
  registration attempt did not satisfy the exact post-registration contract and exercised clean
  task/credential rollback; SID/path normalization was then corrected. The installed task is now
  `Ready`, runs as interactive user `onose` at highest privilege, has secret-free action arguments,
  and next triggers Monday 2026-07-27 at 03:00 local time. Its CurrentUser-DPAPI credential remains
  outside the repository.
- The first triggered scheduler proof, parent execution `v1-20260720T220251Z-48863adc`, received
  `CTRL+C` (`0xC000013A`) after seven completed cases and during runtime-reconnect forward. It is
  not a green. The exact interrupted child `v1-20260720T221040Z-2f50a1df` has no run directory or
  lock on either Linux node only after explicit owner-checked `plan-cleanup` and `cleanup`; fresh
  preflight found Brook inactive and Granite's original PID 803 preserved. This proves the existing
  exact recovery path, but also exposes a resilience gap: forced controller termination cannot run
  in-process final cleanup and would block the next unattended invocation until recovery.
- The clean retry at committed/pushed scheduler commit `7536417` passed parent execution
  `v1-20260720T221929Z-238c05e1`. All 12 fresh cases passed deploy/scenario/cleanup; aggregate JSON
  and parsed JUnit agree on **38/38**, redaction is attested, and final baseline restoration passed.
  Independent Windows inspection found zero copies of run CA SHA-256
  `edf1b63e71b634a4985f97cbf5463e3eea242ea086129db66dbf1c3b1254d2e9` in
  `LocalMachine\Root`; Brook finished inactive and Granite remained PID 803. Task Scheduler records
  `LastTaskResult=0`. Operational events prove action start/completion and `IgnoreNew` correctly
  refused an overlapping `StartWhenAvailable` attempt. The profile took 842 seconds (887 seconds
  including its local build); Brook's service case restarted `117035→117373` (`NRestarts=1`). This
  is complete full green **2 of 3**.

## Current repository state

- Workspace: `F:\Files\repo\github\sylin-org\koi`
- Branch/upstream: `dev` tracking `origin/dev`, ahead 0 / behind 0 at handoff time.
- Latest committed/pushed head: `2600230` (`docs: record scheduled full profile`). The centralized
  interruption-recovery implementation, its physical proof, and prerelease-safe channel integration
  are the uncommitted current slice.
- Product artifact and evidence publisher exercised through clean lab/controller commit
  `f4353821290d732580c9a317d36d315db9be7d60`; product binary content remains the truthful-startup
  build from `27b268d` (`fix(runtime): make capability startup truthful`). The Docker relay/evidence
  commit `40ada4c` and unchanged-service correction `2e40840` precede it on `dev`.
- The bounded-soak controller, centralized multi-format evidence publisher, portable DNS recovery
  test correction, and unattended profile orchestrator are committed and pushed on `dev`;
  documentation is the current slice.
- No PR, release, or package publication was made. All run-scoped test deployments were cleaned
  exactly. Full execution `v1-20260720T211813Z-47d0f395` retains byte-comparable
  `preflight-before.json` / `preflight-after.json` at controller commit `3cfb205`; they confirm Brook
  inactive, Granite's original enabled Koi 0.7.0 service still PID 803, deploy readiness on all
  nodes, and restoration of the stable service/artifact/listener baseline.
- Clean release artifacts were built locally at `f435382`: Linux musl SHA-256
  `199a4b46faa3ef5777b949ffd46684f468e279324f4f98c9e9f1369a856f3287` (41,511,128 bytes) and
  Windows SHA-256 `29de2d484f2be187138d2b8b9aa29c687dcf1c357288a04410aca7f6479b3f30`
  (35,896,320 bytes).
- Clean profile-proof artifacts were built locally at `c37fdb6` and rebuilt unchanged at
  controller commit `3cfb205`: Linux musl SHA-256
  `020f9e86694a272e5c066b9d359fa6578e1b4ee0fef3682e629327e0d602497f` (41,510,952 bytes) and
  Windows SHA-256 `c57d4d5dc3d610bf056709223748dc211952d5a19d02ac9d0a2ee4c83c2ddb70`
  (35,896,320 bytes).
- The earlier green Windows lifecycle run remains historical behavioral evidence but its artifact
  manifest names dirty-tree commit `1f3b2a3`. Clean full-profile child
  `v1-20260720T212140Z-eff4595f` now supersedes that provenance gap with the locally rebuilt
  `3cfb205` artifact; do not rewrite the old run's history.

## Evidence that changes the plan

### Facts

- [`docs/testing/whole-story-e2e-surface.md`](docs/testing/whole-story-e2e-surface.md) already
  defines Acts 0–11 for the composed lifecycle. Reuse its public-surface assertions rather than
  inventing another capability inventory.
- [`docs/adr/018-certmesh-integration-test-suite.md`](docs/adr/018-certmesh-integration-test-suite.md)
  records four certmesh tiers. Tier 4 is native Windows plus a Linux container on the same host;
  it is not physical Windows↔Linux validation.
- [`scripts/integration/cross-host-test.sh`](scripts/integration/cross-host-test.sh) drives real
  Linux↔Linux hardware, but it is a state-resetting bespoke script rather than a reusable
  three-node scenario engine.
- [`docs/SURFACES.md`](docs/SURFACES.md) says Koi delegates trust-store implementation tests to
  `os-truststore`; Koi's own CI does not prove the composed native
  install→serve→verify→remove journey.
- Certmesh create/join calls OS root installation **best-effort** and logs failure while allowing
  the protocol operation to succeed (`core_lifecycle.rs` and `core_member.rs`). Therefore join
  success is not trust-install evidence; the hardware harness must query the native store and run
  native TLS clients.
- `koi trust install` targets the system scope. Windows `LocalMachine\Root` requires an already
  elevated process. `koi trust remove` rereads the original PEM path, so the run must retain that
  exact PEM until cleanup finishes.
- The lockfile now resolves `quinn-proto 0.11.15` and `crossbeam-epoch 0.9.20`, clearing
  RUSTSEC-2026-0185 and RUSTSEC-2026-0204. `cargo audit` exits green with two explicitly
  dispositioned upstream warnings: `anyhow 1.0.102` is the newest compatible published release
  but carries RUSTSEC-2026-0190, and `spin 0.9.8` is yanked transitively through
  `mdns-sd -> flume`; neither currently has an available compatible lock-only replacement.
- The latest three scheduled QA runs inspected on 2026-07-19 were red. On the latest run,
  Windows completed 119/129 checks with ten DNS/certmesh/client contract mismatches; Linux/macOS
  startup was masked by `$env:TEMP` use before `Cleanup` exists. The local QA suite has not been
  rerun in this handoff session.
- The focused proxy tests and physical Act 7 now form complementary evidence: the former guards
  data-plane behavior in CI; the latter proves `.internal` DNS, certmesh issuance, native trust,
  and hot rotation as one deployed Linux transaction. Reusable Tier 1 composition remains.
- The local reproduction classified the Windows failures. Eight are deterministic: two `.lan`
  expectations contradict the intentional `.internal` default; `CertmeshStatus.profile`,
  deadline enrollment, `set-policy` (two assertions), and `/certmesh/roster` were deliberately
  removed by P08; and `certmesh log --endpoint` correctly refuses to leak the local breadcrumb DAT
  to an explicit endpoint, so the harness must pass the token explicitly. The other two CI
  failures (`discover`/`subscribe` `.Count`) are PowerShell scalar-vs-array flakes and happened to
  pass locally because events were present.
- Two real public-dashboard drifts were found: it reads removed `certmesh.profile`, and it reads
  removed `listener.running` although the snapshot now carries `listener.state`. Current help and
  several active examples also still present `.lan` despite the intentional `.internal` default.
- The `crates/koi-udp/Cargo.toml` cache warning is caused by an actual UTF-8 BOM (`EF BB BF`), not
  malformed TOML content.
- The former TOTP test retry was masking a credential-ownership problem rather than a 30-second
  clock rollover: all TOTP slots used the same platform label. Versioned per-slot labels are the
  single evaluation point now; isolated data roots no longer overwrite one another, while v1
  tables continue to resolve their legacy labels.

### V1-10 implementation deviations (2026-08-23, numbered per house rules)

- **D1 — wiring chokepoint:** the fan-out spawns once inside `koi_serve::serve()` next to
  the event forwarder, not separately in the binary and koi-embedded as ADR §1 implied.
  Every boot path through `serve()` inherits it by construction; `serve_adaptive` (embedded)
  does **not** yet spawn it — explicit follow-up before any parity claim.
- **D2 — queue semantics:** the drafted per-sink mpsc queue (256, drop-oldest) is replaced
  by one broadcast receiver per sink: `Lagged` *is* drop-oldest against the shared buffer,
  with fewer moving parts. Overflow diagnostic fires once per episode and closes on the
  next successful delivery.
- **D3 — manifest over config subsystem:** no TOML config file exists to host ADR's
  `[webhooks]`; sinks load from a JSON manifest via `--webhooks <path>` / `KOI_WEBHOOKS`.
  Parse errors are loud (`tracing::error!`) with fan-out disabled — non-fatal boot,
  matching the mDNS-init precedent.
- **D4 — envelope versioning:** SSE events carry no version field; the webhook envelope's
  `v: 1` versions the *envelope* itself.
- **D5 — diagnostics channel:** `webhook.*` diagnostics are injected onto the shared
  `event_tx` (recursion-guarded by event-type prefix) so sinks and dashboard see them;
  no separate channel was added.
- **D6 — crypto placement:** HMAC-SHA256 lives in `koi_crypto::hmac` (subdomain boundary),
  not inline in compose; RFC 4231 case-2 pinned.
- **D7 — flag name pinned by hardware:** the manifest flag is explicitly `--webhooks`
  (`#[arg(long = "webhooks")]`); clap's derived `--webhooks-manifest` was caught live by the
  first physical run, not by any local gate — recorded as a worked example of the
  CI-green ≠ works-on-hardware directive.
- **D8 — crashed-daemon cleanup tolerance:** `stop_webhook_daemon` (lab) kills a live
  run-owned PID or removes only its own stale PID marker; the generic stop script assumes a
  live process and was never modified.
- **D9 — diagnosis semantics aligned to ADR-027 (hardware finding):** the renewal check's
  hardcoded `RENEW_SOON_DAYS = 7` warn — sensible under 90-day leaves — degraded *every*
  healthy leaf under 7-day defaults (caught by the first physical lifecycle run: member
  diagnosis `degraded`/"leaf expires soon (in 6 days)"). The in-scheduled-window state is
  now Ok ("leaf in scheduled renewal window … renews automatically"); Warn-on-soon is gone;
  expired remains Red. Repeated renewal failures still surface via `CertRenewalFailed`
  events and Red-at-expiry. Unit test replaced:
  `renewal_due_soon_is_a_warning_not_a_failure` →
  `scheduled_renewal_window_is_healthy_not_degraded`.
- **D10 — embedded parity closed programmatically (2026-08-24):** `serve_adaptive` itself
  is only a connection dispatcher and owns no event stream, so "wire koi-embedded
  identically" resolves to the instance's `start()`: `KoiConfig.webhooks` (default empty)
  feeds the same `spawn_webhook_fanout` engine next to the shared event forwarder, with
  `/v1/status` reporting parity via `HttpConfig.webhooks`. Sinks ride the dashboard event
  stream, so they require `dashboard_enabled && http_enabled`; configured sinks without
  that stream log one loud warning and stay inert. Proven by
  `crates/koi-embedded/tests/webhook_embedded.rs`: a configured sink receives a signed
  `dns.updated` over real TCP and `/v1/status` reports `{enabled:true, sinks:1}`.
- **D11 — management-plane mounting shape (2026-08-24, corrected same day):** ADR-026 §5
  offered two sanctioned transports; this landing extends the existing inter-node mTLS
  listener (`5642` style) rather than adding a second port: `TrustPlaneConfig.mgmt_mcp`
  mounts `/v1/mcp` behind a per-request CN → roster guard
  (`CertmeshCore::authorize_principal`). Named rejections reuse the shared
  `ErrorBody {error, message}` contract with the ADR-020 reason as the message prefix
  (`unknown_signer: …`) instead of extending the shared type. The guard is coarse by
  design (§5): any active principal ≈ DAT authority minus human-only surfaces;
  `/v1/certmesh/*` CA administration remains off the management router.
  **Correction (hardware finding):** the initial wiring coupled `mgmt_mcp` to
  `--no-mcp-http`; the first physical run proved that wrong — the certmesh lab profile
  disables loopback MCP and got a 404 management plane. The switch is now an independent
  `--no-mgmt-mcp` / `KOI_NO_MGMT_MCP` (default on), per §7 additivity; see D14.
- **D12 — audit attribution scope (2026-08-24):** §6 landed as (a) named failure events
  for principal authorization (`mtls_unknown_cn` / `mtls_expired_cn` /
  `mtls_revoked_rejected`, each carrying the CN), and (b) credential provenance on
  enrollment audits (`member_joined.via = invite|totp`, plus the existing `role`).
  Per-mutation actor fields across every domain handler are deferred to the V1-11 SDK
  slice, where callers self-identify; until then successful MCP sessions attribute at
  the transport layer only (tracing), not the audit log.
- **D13 — invite role binding strengthens §4 (2026-08-24):** the ADR specified role on
  the enroll body only; implementation additionally lets the operator bind the role at
  mint time (`invite --client` → `InviteRequest.role`), enforced CA-side
  (`enroll_role_mismatch`, token burned on attempt). Unbound invites preserve the old
  any-role behavior; legacy stores deserialize unbound.
- **D14 — generic-TLS hostname verification is a feature boundary (hardware finding,
  2026-08-24):** OpenSSL curl refuses the management plane when dialed by IP because
  Koi leaves carry DNS SANs only — correct behavior, and deliberately different from
  Koi's own pinned-CA client, which relaxes the name check for LAN realities. The
  physical lane therefore dials `<host>.internal` via curl `--resolve` onto the node's
  real address (verification honest against a carried SAN, traffic still cross-host).
  Documented as the principal-consumer contract: dial principals by SAN name.
- **V1-10 doc closure:** capability card `docs/reference/cards/webhook-events.md`
  (verified, physical runs cited) + cards index + SURFACES row + full-profile membership
  (`WebhookFanout` forward/reverse inserted after reconnect; profile policy test updated to
  14 cases).

### Working design choices — revise when evidence warrants

- Build a non-published structured lab controller (`tools/koi-lab`) and keep PowerShell limited to
  provisioning, Windows elevation, and native service operations. Product assertions should use
  typed HTTP/JSON, protocol clients, IPC, and native OS tools, not formatted CLI text.
- Use one node abstraction with local-Windows and SSH-Linux drivers, one run inventory, one
  distributed lab lock, one artifact/report format, and reusable scenarios.
- Separate non-privileged protocol tests from privileged native service/trust/resolver tests.
- Build once per run, record commit and SHA-256 hashes, and deploy the same musl artifact to both
  Linux nodes.
- Completed check-bearing scenarios publish JSON + JUnit + readable summaries through one
  redaction-enforcing chokepoint. Preserve diagnostic artifacts on failure without retaining
  DATs, invites, private keys, or sensitive environment data.
- Never change host clocks for expiry tests. Cover deterministic time boundaries below the
  hardware tier; use hardware for real transport, native stores, lifecycle, and integration.

## Epic ledger

| ID | Workstream | Status | Acceptance evidence |
| --- | --- | --- | --- |
| V1-00 | Reconcile the acceptance contract and restore a trustworthy baseline | **complete — 2026-07-19** | Windows QA 128/128 + 2 skips; concurrency 50/50; fmt, all-feature clippy, full locked tests, audit and release build green; local Docker Linux certmesh exchange green; public contract/docs/dashboard aligned |
| V1-01 | Lab inventory, preflight, locking, artifact identity, deployment and exact cleanup | **complete — 2026-07-19** | All three nodes identified; host keys pinned; prerequisites/time/ports checked; concurrent run refused with owner; identical binaries verified; dry-run and exact cleanup removed only run-owned state; original service/binaries preserved |
| V1-02 | Certmesh protocol and native trust role rotations | **complete — 2026-07-19** | Forward and reverse Linux rotations plus the elevated Windows-client rotation pass fail-before, exact install, native clients, wrong-host rejection, tracked removal, fail-after, and full-store restoration. Windows additionally proves exact `LocalMachine\Root` SHA-256 identity, Schannel `curl.exe`, `Invoke-WebRequest`, and byte-exact hosts restoration. Configured `.internal` issuance is centralized. |
| V1-03 | Certificate lifecycle and adversarial trust cases | **in progress — Linux lifecycle/cold recovery and Windows lifecycle green** | Both Linux roles prove wrong-pin refusal, mode-0600 custody, key/leaf/chain/SAN integrity, renewal/key rotation, restart, revocation→RED and generic-TLS limits; both also survive encrypted backup, exact data loss, host-bound restore, locked restart and renewed mTLS continuity. Elevated Windows now proves SID-based custody, key/cert rotation and correspondence, CA-roster convergence, exact owned-child restart with identity/diagnosis/Schannel proxy continuity, revocation→RED/self-revoked, and mutation-free renewal/rejoin refusal. Windows cold recovery remains unclaimed. |
| V1-04 | Real whole-story capability surface | **in progress — physical Linux story + portable Tier-1 aggregation green** | Acts 0, 3, 4, 5, 6, 7, 8, 10, and 11 plus real ACME dns-01 pass physically in both Linux directions. Two concurrent real local daemons now additionally prove the centralized HTTP status/host, dashboard, and authenticated MCP aggregation surfaces. Physical Windows whole-story breadth remains. |
| V1-05 | Resilience, reconnect, fault and soak lanes | **in progress — startup, event reconnect, DNS recovery, Linux systemd supervision, and bounded soak physical** | Always-on regressions and Brook↔Granite rotations prove startup reconstruction, an isolated Docker event-stream fault, and DNS stop/bind-failure/retry in both directions. Brook's transient-systemd lane proves READY/restart-on-failure, while the bounded soak repeatedly proves complete container derivation/reversal and periodic restart reconstruction. Public install/uninstall, other safe faults, and a scheduled 6–24 hour release soak remain. |
| V1-06 | Automation, evidence ledger and v1 release gate | **in progress — interruption recovery physically green; installed scheduler + full green 2/3 on 2026-07-20** | Every completed check-bearing scenario emits redaction-gated JSON, JUnit, and readable summaries from one publisher. Profiles journal each child identity before mutation, heartbeat live ownership, archive successful transactions, and expose one stale recovery command that reuses exact local/remote cleanup and baseline comparison. Controlled execution `v1-20260720T232552Z-d5dfe569` was killed after child `v1-20260720T232601Z-11b15882` owned locks and staged directories on both Linux nodes; stale recovery removed it and passed 3/3 with baseline restoration. Prepared-only and post-cleanup interruption shapes also passed. The installed task's clean retry passed 12/12 cases and aggregate 38/38. Full green 3/3 and the exact-RC soak remain stable-release evidence, not an rc.1 publication prerequisite. |
| V1-07 | Adoption/public-surface polish backed by proved behavior | **in progress — identity, publication foundation, and RC-channel policy locally complete** | ADR-024 canonizes “Let everything local find, trust, and talk” plus Find/Trust/Connect; ADR-025 establishes one attested artifact contract, no-build cargo-binstall metadata, tested npx bootstrap, gated OIDC publication, and one stable/prerelease evaluator. RCs cannot advance stable GitHub/GHCR/npm defaults; tag identity and exact crates.io propagation fail closed. Hosted RC dry run, registry activation, native-manager channels, evidence-gated compatibility claims and golden demo remain. |
| V1-08 | Principal identity for non-human callers (ADR-026) | **complete — implementation + Tier-2 real-binary lifecycle + physical lane green both Linux rotations, 2026-08-24** | Client-role leaves: clientAuth-only EKU + digitalSignature-only KU (`client_profile_refuses_server_auth_and_key_encipherment`). Role-bound invites (`invite --client`) enforced CA-side with burn-on-mismatch. Management plane: `/v1/mcp` on the mTLS listener behind `CertmeshCore::authorize_principal` — named rejections audited; independent `--no-mgmt-mcp` switch (D11 correction/D14). Tier-2 run proves local keygen + CSR custody, tokenless raw join, MCP initialize over mTLS = 200, revocation → 403 named reason. Physical `mgmt-principal` forward+reverse (`v1-20260824T122847Z-5d021108`): whole story across the real LAN with musl SHA-256 `233345caf7166f7304c9580cb42d8eeffe3328db4742fc4f697449e5a604183f`, exact cleanup, baseline restored. Enrollment audits carry role + `via`; per-mutation actor attribution deferred per D12. SURFACES row added; overview/security-model/api-authentication synced to the amended ADR-024 wording. Owed: MCP/certmesh capability-card mentions of principals (docs-only). |
| V1-09 | Short-lived leaves as default posture (ADR-027) | **in progress — implemented; unit + physical lifecycle green both Linux rotations 2026-08-24** | Defaults 7/3/1 live in `CertPolicy::default`, `ca::DEFAULT_LEAF_LIFETIME_DAYS`, `csr::DEFAULT_CSR_VALIDITY_DAYS`; oracle test `default_policy_is_the_adr_027_short_lived_posture` pins them. Three tests re-oracled to the 7-day schedule (ca round-trip, self-enroll identity, invite enrollment). **Hardware found a real defect**: `diagnosis.rs` warned "leaf expires soon" from a hardcoded 7-day constant sized for 90-day leaves — every healthy leaf would have been permanently Degraded (deviation D9). Fixed: in-scheduled-window is Ok; Warn reserved for anomalies; expired stays Red. Overview revocation bullet synced to the ≤8-day bound. Physical `certmesh-lifecycle` green forward run `v1-20260824T004010Z-ca93a718` and reverse run `v1-20260824T004259Z-acd1d6ca` (join/custody/SANs/key-rotating renewal/restart/revocation→RED), musl SHA-256 `0c7de764a824e4b025489f4868461a0e9ad06eeb6f3513e1e8fca25a6880fbc1`; exact cleanup + baseline restored (Brook not-found, Granite active/enabled koi 0.7.0). Owed: soak-lane re-run at the new cadence; long-haul posture documented in the certmesh capability card. |
| V1-10 | Outbound webhook fan-out (ADR-028) | **complete — engine + embedded parity + docs; local suites + physical cross-host green both Linux rotations 2026-08-23/24** | Local: 7 unit tests (RFC 4231 HMAC vector, redaction guard) + 3 real-TCP integration tests (exact headers/envelope, retry-after-500 with identical id/body, disabled-sink isolation) + embedded parity test (`webhook_embedded.rs`: signed `dns.updated` delivered to a configured sink over real TCP, `/v1/status` reports it); fmt/clippy/test green across crypto/compose/serve/embedded/binary. Physical (`webhook-fanout`, new koi-lab scenario): forward run brook→granite captured **45 deliveries**, reverse granite→brook **41**, every delivery HMAC-valid at receive time, envelope v=1 shape-correct, types observed `dns.updated/dns.txt_updated/mdns.found/mdns.resolved`, daemon healthy throughout, exact cleanup green, final preflight preserved Brook not-found and Granite's active/enabled koi 0.7.0 service. Musl artifact SHA-256 `db952c768413091c412a4048d7d6d2278633f7397f9a665e66392c89baab6719`. Hardware caught a real CLI defect (clap derived `--webhooks-manifest`; lab passes `--webhooks`) — fixed with explicit long name. Deviations D1–D6 below; D1's owed embedded wiring closed per D10 on 2026-08-24. |
| V1-11 | Standard seed + SDK betas | **in progress - spec + vector + SDK enroll-side complete; only publication remains (gated on stable 1.0.0 + external authority)** | Step 1: the language-neutral trust spec (`docs/reference/trust-protocol.md`, ADR-020-era) gained the **Agent-Door section** (8): pinned server-card shape, `_mcp._tcp`/DNS TXT discovery records, both sanctioned auth shapes (DAT loopback / ADR-026 principal over mTLS), and the SAN-name dialing rule; the card is pinned as `docs/reference/vectors/agent-door-card.json` and executed against the Rust impl (`koi-serve http::tests::agent_door_vector_matches_the_impl`). Step 2: `packages/ts` (`@sylin-org/koi-client` 0.1.0-beta.1, zero-dep ESM, node:test, 8/8) + `packages/python` (`sylin-koi-client` 0.1.0b1, stdlib-only, unittest, 8/8) - status/health/posture/card/events-SSE plus enrollment: TS raw-custody CSR generation verified by THREE independent oracles (node crypto self-verify, python cryptography parse+verify, and the real CA issuance path via `crates/koi-certmesh/tests/sdk_csr.rs` fixture); join() never carries the local token to the remote CA; enrollWithLocalDaemon drives member-csr/join/member-cert with a shipped-key custody tripwire. Owed: publication only (external authority required). |
| V1-12 | Desktop control plane (ADR-031) | **proposed - ADR ratified, basics queued** | Config substrate (versioned TOML, CLI>env>file>defaults, loud unknown keys, `config init`), L0 welcome contract, L1 tray MVP (posture icon + menu over loopback/DAT), pane = dashboard sections. |
| V1-13 | Windows 1:1 parity program (ADR-032) - **GATES STABLE 1.0** | **accepted - matrix defined; P1 foundations next** | W1 SCM supervision, W2 named-pipe IPC, W4 redo on current tree, W5-W9+W12 breadth both rotations, W10 cold recovery; W3 done rc.2-era; W11 tagged exclusion. Stable gate = all rows green in extended full profile + clean soak incl. Windows. |

## Deferred to 1.1 (consciously, 2026-08-23)

- mDNS cross-subnet reflector — new network subsystem; revisit with its own ADR.
- Terraform/OpenTofu provider — separate repository/artifact; accompanies but cannot join the binary's release.
- Grafana dashboard/datasource — same separate-artifact nature.
- Per-principal scopes/RBAC on the management plane (ADR-026 explicitly defers this).

## Certmesh/native-trust acceptance matrix

Each of the three V1-02 role rotations must prove:

1. Native TLS verification fails before root installation.
2. Invite fingerprint pins the intended CA; member key/CSR originate locally; no private key crosses
   enrollment; Linux mode and Windows ACL checks pass.
3. `koi trust install` installs the exact CA fingerprint; native store inspection and
   `koi trust list` agree.
4. A real service behind Koi's TLS proxy is accepted cross-machine without `-k` or a custom CA
   override by Windows Schannel (`curl.exe` and `Invoke-WebRequest`) and Linux native clients
   (`curl`, `openssl s_client -verify_return_error`). Wrong hostname still fails.
5. TLS-only tests use an explicit address mapping first so DNS failures cannot masquerade as trust
   failures. A separate privileged lane proves real `.internal` system resolver configuration and
   restores it exactly.
6. Renewal rotates the member key; restart preserves state; revocation blocks Koi renewal/rejoin
   and makes diagnosis red. Generic TLS acceptance of an unexpired revoked leaf is recorded as the
   documented non-CRL/OCSP limitation, not misreported as a test failure.
7. `koi trust remove` removes only the recorded fingerprint; a fresh native client fails afterward;
   service, resolver, files and processes return to their captured baseline.

## Execution profiles

- **smoke:** connectivity, artifact identity, deploy, health, mDNS and one join; target ~5 minutes.
- **certmesh:** all role rotations and native trust lifecycle; measured 4m17s on the current lab.
- **linux:** every full-profile case that runs on the two Linux hosts (15 scenarios); added 2026-08-24, first run 1-20260824T142133Z-72cb57bf 47/47.
- **full:** every capability and composed whole story incl. the elevated Windows lane; measured 12m57s on the current lab (12-case era).
- **soak:** repeated events, restarts, renewals and controlled faults; 6–24 hours.

Hardware execution is not a PR gate initially because the lab is shared and finite. Local/unit and
container tiers remain PR gates; hardware smoke runs frequently; certmesh/full gate major phases and
releases; soak is scheduled or explicitly invoked.

## Resume here

1. ~~Ratify ADR-026/027/028; implement V1-10 webhooks~~ (done — V1-10 complete
   2026-08-24, V1-09 implemented + physically green, **V1-08 complete incl. physical
   lane 2026-08-24**). **Next: V1-11** — language-neutral trust/Agent-Door spec page in
   `docs/reference/` with pinned conformance vectors (Posture/Envelope/Sealed/handshake
   per STACK-0001 D7) executable against the Rust implementation, then TS + Python SDK
   betas against the frozen HTTP API (publication stays gated on stable 1.0.0 + explicit
   external authority). Also owed docs-only: MCP/certmesh capability-card mentions of
   principals. Each landing keeps its full local gate (`fmt`, all-feature clippy
   `-D warnings`, locked workspace tests, audit).
2. After V1-08..V1-11 land: re-prep the release version, hosted Release dry run, then — only
   with explicit external-publication authority — tag/publish `1.0.0-rc.1`.
3. Validate that exact distributed candidate through full green 3/3 and the bounded soak
   before stable `1.0.0`.
4. Design the public Linux install/uninstall contract only if fixed unit/binary/data paths and the
   default DNS-port conflict can be made byte-exact reversible. The safer systemd supervision proof
   is complete; do not broaden it into an install claim.
5. Implement and physically execute Windows cold recovery only if exact encrypted backup/data-loss/
   restore ownership can stay within the tracked Windows transaction; until then leave it unclaimed.
6. Upstream the Debian dangling-symlink fix to `os-truststore` when separate repository/publication
   authority exists; then remove Koi lab's guarded compatibility branch.

## Implementation map

- `tests/integration.ps1`, `tests/concurrency.ps1`: current scheduled QA harness and immediate V1-00 repair surface.
- `.github/workflows/qa.yml`, `.github/workflows/ci.yml`: existing gates and eventual profile wiring.
- `docs/testing/whole-story-e2e-surface.md`: canonical Acts 0–11; reconcile stale constraints.
- `docs/adr/018-certmesh-integration-test-suite.md`: existing certmesh tiers and cross-platform history.
- `docs/SURFACES.md`: honesty/rotation ledger; update only with real evidence.
- `docs/testing/integration-hosts.md`: physical-host runbook and last hardware findings.
- `scripts/integration/deploy.ps1`, `scripts/integration/cross-host-test.sh`,
  `scripts/cross-platform-certmesh.ps1`: reuse lessons, then retire duplication deliberately.
- `crates/koi-embedded/tests/whole_story.rs`, `crates/koi/tests/two_daemon_certmesh.rs`:
  existing reusable scenario behavior and assertions.
- `crates/koi-certmesh/src/core_lifecycle.rs`, `core_member.rs`, `diagnosis.rs`: best-effort trust installation and diagnostic semantics the hardware lane must prove.
- `crates/koi/src/commands/trust.rs`: explicit root install/list/remove/export; source PEM must survive through removal.
- `crates/koi-dns/src/http.rs`, `resolver.rs`, `crates/koi-client/src/lib.rs`,
  `crates/koi/src/commands/dns.rs`: authenticated exact-value ephemeral TXT publication surface.
- `crates/koi-runtime/src/lib.rs`, `crates/koi-compose/src/orchestrator.rs`: centralized lifecycle
  ingestion and the always-on synthetic derivation/reversal story.
- `tools/koi-lab/src/story.rs`, `acme.rs`, `lab.rs`: physical whole-story composition, real ACME
  client, centralized certmesh provisioning, native trust/rotation proof, and compensating cleanup.
- `.github/workflows/release.yml`, `scripts/release-manifest.mjs`, `packages/npm/`,
  `crates/koi/Cargo.toml`: artifact-first publication contract and thin channel consumers.
- `tools/koi-lab/`: controller, inventory, node drivers, scenarios, fixtures, and reports.
- Sibling `F:\Files\repo\github\sylin-org\os-tools\crates\os-truststore`: native trust-store implementation and lower-tier tests; do not duplicate it inside Koi.

## Do not redo

- Do not repeat broad repository/market/ecosystem discovery; use `.oss-adoption/current/` for that evidence.
- Do not treat ping failure or a sandbox-denied socket as proof a lab host is down. Both hosts were
  authenticated successfully over SSH after using the permitted network context.
- Do not extend the current bash script into a second monolithic source of truth. Reuse its proven
  operational lessons in the structured lab runner.
- Do not parse human CLI tables for contract assertions when JSON/HTTP/protocol output exists.
- Do not infer OS trust from a successful certmesh create/join; query the native store and execute a
  native TLS verifier.
- Do not use `-k`, broad certificate deletion, unpinned SSH, hard-coded credentials in new work, or
  host clock changes to manufacture green results.
- Do not claim the epic or a capability complete because a lower tier passes. Record the tier and
  the exact evidence.

## Current validation and evidence still owed

- The current tree passes `cargo fmt --all -- --check`, all-target/all-feature Clippy with
  `-D warnings`, `cargo test --workspace --all-features --locked`, `cargo audit`, the surface-ledger
  lint, and `git diff --check` on 2026-07-20 after all work in this handoff. Focused counts are
  `koi-runtime` 49, `koi-compose` 14, `koi-lab` 45, and the real-binary two-daemon integration 2;
  all passed. The gate caught and corrected a Windows test-only UDP/TCP ephemeral-port assumption;
  the focused retry and complete workspace rerun are green. Audit exits 0 with the two dispositioned
  allowed warnings (`anyhow` RUSTSEC-2026-0190 and yanked transitive `spin 0.9.8`).
- V1-00 is locally complete. Hosted Linux/macOS scheduled-QA evidence remains unavailable until
  changes are intentionally published to CI; do not conflate the local Linux container certmesh
  gate with the full cross-platform PowerShell QA lane.
- All three native-trust rotations are physically proven, including exact Windows
  `LocalMachine\Root` install/remove, Schannel and `Invoke-WebRequest`, hosts restoration, and full
  store-baseline restoration. Windows run-owned ACL/key custody, renewal, exact restart continuity,
  revocation, and mutation-free refusal are also proven. No permanent Windows trust root, Koi
  service, process, hosts mapping, or run-owned data remains.
- Windows cold recovery, public install/uninstall, remaining safe fault lanes, long soak,
  and the final complete full green are outstanding. Installed
  scheduled invocation is physically green. Unattended profile
  orchestration is physically green for both Linux smoke directions. Linux systemd supervision and
  the bounded short soak are physically green. Portable Tier-1 HTTP/dashboard/MCP breadth and
  deterministic Docker reconnect are green, including the physical stream fault and DNS
  stop/bind-failure/retry in both Linux role directions. Physical Linux Acts
  0/3/4/5/6/7/8/10/11 plus ACME and daemon-restart startup reconciliation are also complete in
  both directions.
## Open basket

- **Now:** ratify ADR-026/027/028; implement V1-10 → V1-09 → V1-08 with full local gates per landing.
- **Next:** V1-11 spec/vectors + SDK betas; then re-prep the release version, hosted Release dry run,
  and — with explicit publication authority — publish the candidate; complete full green 3/3 and
  soak the exact published candidate for 6–24 hours before stable `1.0.0`.
- **Later in epic:** Windows cold recovery, safe remaining faults, and the reversible public Linux
  install/uninstall contract where their exact mutation boundaries can be proved.
- **Deferred:** remaining V1-07 evidence-backed adoption/golden-demo work; first npm publication
  and trusted-publisher activation; GHCR public-visibility verification/fix; WinGet/Homebrew
  channel creation; any other external publication; and the 1.1 section items (mDNS reflector,
  Terraform provider, Grafana dashboard, per-principal scopes).
- **Related readiness debt:** runtime list/watch reliability, off-loopback management transport,
  embedded data-root isolation, partner label semantics, Prometheus/Tailscale contract proof,
  and claim/documentation drift remain relevant to the v1 full-surface gate. The green Release
  dry run also emitted GitHub's non-blocking Node 20 deprecation annotation for pinned
  `actions/checkout@v4` / `actions/upload-artifact@v4`; update and revalidate the official action
  majors in V1-06 before the v1 release gate.
