# PH-001 — Productization hardening: delight under real conditions

**Status:** active
**Started:** 2026-09-02
**Entry point:** `run fleet/task.md`
**Scope:** Windows, CachyOS, Bluefin, Alpine/musl, and headless Debian

## Objective

Turn Koi's coherent early-beta foundation into an evidence-backed daily driver across
the supported fleet without expanding the feature set. A user should install Koi once,
receive the best facilities already present on the OS, retain a dependable native
fallback, and recover from ordinary machine and network churn without learning Koi's
internal architecture.

This epic hardens the existing Find → Name → Trust → Serve/Pond promise. It does not
add another domain, daemon, updater, provider facade, remote-control plane, generic
plugin system, reflector, telemetry service, or project-management layer.

## Product law

- One DDD-aligned monolith and one real installed Koi per machine.
- Adapters own detection, native resources, capabilities, recovery, and teardown.
- Orchestration owns policy and desired-vs-observed reconciliation.
- Existing OS facilities win when genuinely usable; native Koi is always available at
  lower priority.
- Platform facts come from real operations, not filenames, registry folklore, stubs,
  or optimistic messages.
- Safe expected failures recover automatically. User action is reserved for boundaries
  Koi cannot legitimately cross and names one precise remedy.
- No new advertised capability until this epic closes.

## Dependency map

```text
PH-0 → PH-1 → PH-2 ─┐
  └──────→ PH-3 ────┼→ PH-4 → PH-5
```

PH-0 and PH-1 proceed per hat; one slow OS does not block another's local correction.
PH-3 may run beside PH-1/2 but must close before the frozen-candidate matrix.

| ID | Workstream | State | Exit gate |
|---|---|---|---|
| PH-0 | Freeze and reconcile the product contract | **green at frozen source** | Every advertised capability, OS, artifact, and install path maps to a current real gate or an explicit unverified/unsupported state; stale claims are corrected. |
| PH-1 | Platform truth and durable lifecycle | **green fleet-wide** | Clean install, in-place upgrade, failed-upgrade recovery, reboot, uninstall, and reinstall use product-owned paths and preserve intended identity/configuration. |
| PH-2 | Environmental recovery | **green fleet-wide** | Process crash, provider loss/return, link/IP churn, firewall change, runtime disconnect, boot, lock, and sleep/resume recover without duplicates or manual re-arming. |
| PH-3 | Security-boundary hardening | **green fleet-wide** | Local-control identity, Pond allowlist, operator auth, installer privilege, key custody, hostile LAN input, and resource bounds have executable negative gates; no unresolved critical/high finding remains. |
| PH-4 | Installed whole-story matrix | **green fleet-wide at `e49bfe2b3e403fa87d4b8b237b49f3bb9e5cb5ef`** | One frozen source revision completes Find → Name → Trust → Serve/Pond using installed artifacts across physical OS/provider families. |
| PH-5 | Onboarding, diagnostics, and soak | **active — installed-entry and collector convergence** | Fresh users reach a useful result without checkout/toolchain paths; the exact candidate survives a preferably 24-hour mixed-OS soak with bounded resources and exact restoration. |

### 2026-09-03 12:03 EDT PH-4 green; PH-5 dispatched

PH-4 is accepted. Every hat rebuilt and installed the exact frozen source, or an
OS-native package whose payload came from that exact source, and recorded a healthy
singleton deployment:

| Hat | Installed artifact SHA-256 | Accepted physical closure |
|---|---|---|
| Windows | `9c4998461d3d0760a75c78dc2075d8d095666aa91626146af794f68d49e4b588` | local whole story; `ph4-e49b-win-avahi-01`; `ph4-e49b-win-native-02` |
| CachyOS | `f0e999b0077eb25935f1ad563aee33f2e659ffde915d3f3c55f5aa568691682b` | installed whole story/Pond; Avahi/resolve1↔native lane; reboot and peer restoration |
| Bluefin | `288362b8ae909d655f683f290f2b34bd5d8cb802a1184a0cebf27a1b3219e200` | immutable systemd/GNOME whole story and exact-source replacement |
| Alpine | `095371b9ed13cde254214155aa231db9333342c35255717654299fcd514e9941` | signed APK/OpenRC/musl whole story and Windows native peer |
| Debian | `51682d682f155139f0e0d4c7f2bdce6b2e237f6bbf464ccdbfc7b30a7251cbbb` | headless whole story and `ph4-e49b-debian-pond-01` |

The final Windows/native run kept Windows PID `5312` and Alpine daemon/supervisor PIDs
`2023`/`2022` fixed through five generations, bidirectional ordinary and
explicit-address discovery, address/TXT/interface checks, a continuous subscription,
real withdrawal, Bonjour loss/fallback/return, and exact restoration. Together with
the accepted Windows/Avahi and Linux Avahi/resolve1/native lanes, this closes every
frozen-candidate provider family. The Windows correction was the only product delta;
unchanged Linux executable paths were rebuilt for exact provenance and their
byte-identical physical evidence remained valid. No open critical/high finding or
unrestored fleet state remains.

PH-5 begins with two deliberately separate claims:

1. **Installed entry and diagnostics.** Each hat starts from a normal user/session and
   a neutral working directory with no checkout, Cargo, alternate data root, endpoint,
   or token override in the user path. Use only the installed CLI, package/Start-menu
   workbench, local-control discovery, and returned Pond URL. Prove that status,
   provider selection, trust diagnosis, sharing state, and one representative
   unavailable/recovery explanation lead a new operator to a useful next action. Do
   not destroy the accepted machine identity merely to simulate freshness.
2. **One installed-service observation model.** Evolve the existing
   `installed-service-collect` boundary rather than adding per-hat scripts. One neutral
   sampler/verdict/evidence core owns cadence, bounds, recovery decisions, redaction,
   and aggregation. Thin systemd, OpenRC, and Windows SCM observers own only native
   detection plus service/process/resource facts. Missing native counters are explicit,
   never zero-filled. A cross-host success must exercise a real Koi surface; the former
   TCP connection to peer SSH port 22 is useful reachability preflight but cannot close
   the product soak.
3. **Short canary before duration.** Every observer must pass a short run against the
   exact installed artifact and a Koi-owned peer surface while proving PID/image,
   health, RSS, handles/descriptors, threads/tasks where real, cache size, provider
   generation/routes, retry and desired/established counts, and bounded recovery. The
   product remains the sole installed daemon; a harness executable may come from the
   checkout, but the user journey and Koi process may not.
4. **One coordinated soak.** After all short canaries are green, CachyOS names one run
   ID and Debian owns the aggregate timeline. Every hat samples its own installed
   service while run-owned Koi traffic forms a physical peer ring. Use 24 hours for
   release-quality evidence; six hours is the minimum engineering acceptance. Faults
   are serial: each hat owns exactly one previously proven representative
   service/provider/network recovery window, with explicit start/end markers and
   bounded reconvergence. No two system mutations overlap.
5. **Closure.** Restore Pond/firewall/provider/network/session and run-owned product
   state exactly, remove credentials and recovery helpers, retain one healthy intended
   Koi/workbench per machine, and rerun each platform's full locked native gates. A
   harness-only correction does not move `e49bfe2`; any product, dependency,
   installer, package-behavior, or shipped-asset correction reopens PH-4 and requires
   an explicit new freeze.

Ownership stays small: Debian owns the neutral collector/aggregate and its systemd
observer; Windows owns SCM observation; Alpine owns OpenRC observation; CachyOS and
Bluefin independently accept the systemd path and their desktop entry journeys;
CachyOS coordinates the canary ring, serial fault schedule, and final reconciliation.

### 2026-09-03 11:48 EDT Windows↔native exact-source acceptance checkpoint

Windows run `ph4-e49b-win-native-02` passed against Alpine's unchanged exact-source
native/OpenRC peer. The installed Windows SCM daemon remained sole PID `5312` at
SHA-256 `9c4998461d3d0760a75c78dc2075d8d095666aa91626146af794f68d49e4b588`;
Alpine remained daemon PID `2023` under supervisor PID `2022` at SHA-256
`095371b9ed13cde254214155aa231db9333342c35255717654299fcd514e9941`.
Bidirectional ordinary and explicit-address discovery preserved exact address, TXT,
and interface truth through native baseline, Bonjour promotion, provider loss/native
fallback, Bonjour return, and final native restoration. One Windows subscription
survived all five generations and observed Alpine removal; Alpine independently proved
both Windows records absent after withdrawal. Counts converged with no pending/failed
materializations, no daemon or supervisor restarted, and both hosts restored their
exact service, provider, network, firewall, publication, and workbench baselines.

The first invocation stopped before mutation on a harness-only StrictMode check of
Alpine's intentionally absent direct-resolve route. The corrected rerun tested property
absence and retained all product assertions. No product, dependency, installer,
package recipe, or shipped asset changed, so the frozen source does not move.

All five exact-source artifact entries, both final Windows provider lanes, Debian's
exact-source Pond rerun, and the unchanged Linux provider evidence are now present on
`dev`. CachyOS owns the final PH-4 reconciliation. PH-5 remains prohibited until that
reconciliation marks PH-4 green.

### 2026-09-03 11:36 EDT PH-4 narrowed to the final Windows/native lane

Three exact-source results landed and passed reconciliation. Windows↔CachyOS/Avahi
run `ph4-e49b-win-avahi-01` closed the corrected withdrawal lane with both installed
PIDs/hashes fixed and exact cleanup. Bluefin rebuilt and installed exact `e49bfe2` at
SHA-256 `288362b8ae909d655f683f290f2b34bd5d8cb802a1184a0cebf27a1b3219e200`
without repeating unaffected Linux gates. Debian rebuilt and installed exact `e49bfe2`
at SHA-256 `51682d682f155139f0e0d4c7f2bdce6b2e237f6bbf464ccdbfc7b30a7251cbbb`,
then passed physical Pond run `ph4-e49b-debian-pond-01` against unchanged CachyOS and
restored its shifted service, disabled desire, credentials, packages, and peer boundary
exactly. Alpine rebuilt signed/indexed `e49bfe2` APKs and upgraded the one OpenRC
deployment to `koi-1.0.0_rc2_git20260903-r3`; its stripped installed executable is
SHA-256 `095371b9ed13cde254214155aa231db9333342c35255717654299fcd514e9941`.
The shifted `5651:5654` plan, native routes, stopped/disabled Avahi, singleton daemon
and workbench, durable state, package ownership, repository, and network baseline were
all exact after installation. None found a product defect or moved the freeze.

CachyOS then passed a read-only post-peer audit after an ordinary machine reboot. The
exact installed artifact remained SHA-256
`f0e999b0077eb25935f1ad563aee33f2e659ffde915d3f3c55f5aa568691682b`;
systemd started exactly one healthy PID `721` with zero restarts, Avahi retained all
four routes and one permanent publication, trust remained HEALTHY/Authenticated, Pond
remained disabled and closed, UFW files remained byte-exact, and the real Plasma
session held one package-owned workbench and one SNI item. The previous PID `962933`
was the exact process observed by both completed peer transactions before that reboot,
so the lifecycle change is expected rather than unexplained drift.

The only remaining PH-4 path is now serial and explicit:

1. Windows runs only `ph4-e49b-win-native-02` against the unchanged exact-source
   Alpine peer and
   publishes its final withdrawal/restoration evidence.
2. CachyOS reconciles the five exact-source artifacts and completed physical lanes,
   marks PH-4 green, and dispatches PH-5. No completed gate is repeated and the soak
   does not begin before that lane closes.

### 2026-09-03 10:28 EDT Windows↔Avahi exact-source acceptance checkpoint

Windows run `ph4-e49b-win-avahi-01` passed against CachyOS's unchanged exact-source
Avahi peer. The installed Windows SCM daemon remained sole PID `26508` at SHA-256
`9c4998461d3d0760a75c78dc2075d8d095666aa91626146af794f68d49e4b588`;
CachyOS remained systemd PID `962933` at SHA-256
`f0e999b0077eb25935f1ad563aee33f2e659ffde915d3f3c55f5aa568691682b`.
Bidirectional ordinary and explicit-address discovery preserved address, TXT, and
interface truth through native baseline, Bonjour promotion, provider loss/native
fallback, Bonjour return, and final native restoration. One Windows subscription
survived all generations and observed the CachyOS removal; CachyOS independently
proved both Windows records absent after withdrawal. Counts converged with no pending
or failed materializations, neither daemon restarted, and both hosts restored their
exact service, provider, network, firewall, publication, and workbench baselines.

The first attempt stopped cleanly on a harness-only false identity mismatch because
raw `ip -o addr` output included decreasing DHCP lifetime counters. The accepted rerun
compared stable interface/address identity separately from the exact default route and
retained all product assertions. No product, dependency, installer, or shipped asset
changed, so the frozen source does not move.

The remaining PH-4 critical path is:

1. Alpine, Bluefin, and Debian publish exact-`e49bfe2` installed artifacts.
2. After Alpine is ready, Windows runs only `ph4-e49b-win-native-02`; the accepted
   Avahi lane must not be repeated on unchanged artifacts.
3. Debian reruns only `ph4-e49b-debian-pond-01` from its exact-source artifact.
4. CachyOS reconciles PH-4 after those entries are green. PH-5 remains prohibited.

### 2026-09-03 09:52 EDT CachyOS exact-source acceptance checkpoint

CachyOS rebuilt the release from a clean detached worktree at exact source
`e49bfe2b3e403fa87d4b8b237b49f3bb9e5cb5ef`, passed formatting, script syntax, the
full locked workspace/all-target/all-feature suite, strict clippy, and the locked
release build, then installed it through the public systemd path. The release and
installed `/usr/local/bin/koi` are byte-identical at SHA-256
`f0e999b0077eb25935f1ad563aee33f2e659ffde915d3f3c55f5aa568691682b`
(54,184,944 bytes). Those bytes correctly equal the former Linux artifact because the
source delta is confined to the Windows adapter; provenance was nevertheless rebuilt
and proved from the new freeze rather than inferred.

The serial install changed the sole daemon PID `924696→962933`, retained the standard
port plan without creating `/etc/koi/config.toml`, and ended enabled, active, healthy,
and at `NRestarts=0`. Generation 1 routes publish, explicit publish, browse, and resolve
through Avahi with one desired/established permanent registration; resolve1 and native
remain ready fallbacks. The Authenticated `test-01` identity diagnoses HEALTHY, Pond is
disabled and closed, the UFW/state/unit hashes are exact, and the unchanged packaged
Plasma workbench remains the sole desktop process. Per the Windows-gated change rule,
the already-green Linux whole-story and provider-transition workbooks were not repeated.

This makes CachyOS an unchanged dependency-ready peer for Windows run
`ph4-e49b-win-avahi-01` and Debian run `ph4-e49b-debian-pond-01`. Debian's newly landed
`ph4-5c89-debian-pond-01` PASS validates the physical workbook but explicitly used the
superseded source, so it does not close the exact-source transaction and is dispatched
for a narrow rerun after replacement. PH-4 remains active until every hat records its
exact-source artifact, Windows records both final provider lanes, and Debian records
the exact-source Pond lane.

### 2026-09-03 09:20 EDT Windows withdrawal correction and final re-freeze

The exact Koi source candidate is now
`e49bfe2b3e403fa87d4b8b237b49f3bb9e5cb5ef`. It includes the Windows DNS-SD
withdrawal correction plus the already-landed CachyOS, Bluefin, and Debian evidence
commits. It supersedes and invalidates
`5c89e9de11bf23ab81fd8b5b0778c58477359360`; every final PH-4 installed daemon or
package must be rebuilt from a clean export/detached worktree of this exact source.
Unchanged separately versioned workbench artifacts retain their prior provenance.

Windows run `ph4-5c89-win-native-01` reached every provider phase but exposed that
the official `DnsServiceBrowse` API never delivers peer removal callbacks. The same
long-lived subscription therefore retained Alpine after its acknowledged withdrawal,
and a point resolve returned stale Windows cache data. The Windows adapter now owns an
indefinite `DnsStartMulticastQuery` PTR query, preserves TTL-zero goodbye responses,
normalizes them to the existing provider-neutral `Removed` event, and stops/reclaims
the native query as one lease-owned lifetime. The shared discovery cache and event
projection already owned eviction and needed no OS-specific imitation.

Focused Windows adapter tests, strict clippy, the full locked workspace tests, and a
direct live multicast resolve/withdrawal test passed. A clean exact-source release was
installed through the SCM product path at SHA-256
`9c4998461d3d0760a75c78dc2075d8d095666aa91626146af794f68d49e4b588`.
Physical run `ph4-e49b-win-native-01` then passed generations 1–5 across native,
Bonjour promotion, provider loss/fallback, return, and native restoration; the one
pre-existing Windows subscription observed Alpine resolution and removal. Windows PID
`26508` and Alpine PID `24201`/hash
`4db6a257b9303157bd8dff03887b478b2c8f5a20f777166d35a59f77436a95e9`
stayed fixed, and both hosts restored exact service/provider/network/firewall/count
baselines with no credential or recovery residue. Because Alpine still ran the now
invalidated source during that diagnostic/acceptance proof, the final exact-source
Windows↔native lane waits for Alpine's replacement artifact rather than relabeling it.

The narrowed critical path is:

1. Alpine, CachyOS, Bluefin, and Debian build their native artifact/package from exact
   source `e49bfe2b3e403fa87d4b8b237b49f3bb9e5cb5ef`, run their locked native gates,
   install through their existing product path, and publish artifact/PID/baseline
   readiness. The correction is Windows-gated, so do not repeat already-green Linux
   whole-story, desktop, lifecycle, or provider workbooks solely to create activity.
2. Once Alpine is exact-source ready, Windows reruns only its affected native-peer lane
   as `ph4-e49b-win-native-02`. Once CachyOS is ready, Windows runs the outstanding
   Avahi lane as `ph4-e49b-win-avahi-01`. Only Windows mutates its providers in both.
3. Debian completes its still-pending Pond transaction from the new exact artifact as
   `ph4-e49b-debian-pond-01` after its approved private credential handoff. CachyOS
   remains the read-only peer.
4. CachyOS reconciles PH-4 only after all five exact-source artifact entries and the
   three remaining transactions above are green. PH-5 remains prohibited until then.

### 2026-09-03 PH-4 source re-freeze and execution contract

The exact Koi source candidate is
`5c89e9de11bf23ab81fd8b5b0778c58477359360`. It is already present on
`origin/dev`. Every PH-4 daemon/package artifact must be built from a clean export or
detached worktree of that commit, even while later journal and dispatch commits advance
`dev`. Record both the full source SHA and installed artifact SHA-256. Existing native
workbench artifacts may remain only where their own source and installed bytes are
unchanged; record that separate provenance explicitly.

This supersedes and invalidates `f53d568a871e952576988e543126160bfd41aaaa` and
the intermediate re-freeze `9134b32c87db990f18b09c56038d8c6255607ffa`.
Windows's installed PH-4 transaction proved that the proxy API persisted its supported
`[proxy]` section into the shared `config.toml`, while that same candidate's strict
launch parser rejected the section during the next install or restart. The shared
parser now recognizes and validates the proxy-owned schema without weakening unknown
top-level-key rejection. Alpine's installed PH-4 transaction then proved that the
documented bare `host:port` proxy backend ran and passed real traffic while its derived
HTTP health check falsely reported a URL builder error, and that removal left the stale
derived state counted until restart. The shared health projection now normalizes bare
proxy targets and reconciles removed state. Any PH-4 artifact or local verdict built
from either invalidated source must be rebuilt and rerun from the exact re-freeze above.

PH-0 through PH-3 are reconciled green at this boundary. Their final pre-freeze input
includes the accepted Windows SCM recovery correction, Bluefin immutable reboot,
Debian and Alpine ownership-aware installs, and CachyOS runs
`20260903T041144Z-866860` (Avahi/resolve1/native) and
`20260903T041803Z-869519` (Pond through Bluefin). Full native tests, strict clippy,
surface/documentation/publish/embedded checks, one-process invariants, and exact host
restoration are green. The first Pond diagnostic run is deliberately excluded because
its old harness wrote PASS before verifying cleanup; the accepted rerun used the
restoration-gated workbook in the frozen commit.

PH-4 uses the real installed service and production ports. Its whole-story transaction
drives authenticated local control and public product APIs against run-owned resources
on the standing deployment. It must not use the legacy `koi-lab capability-story` mode
as acceptance: that older mode stops standing services and launches isolated daemons.
Preserve an existing enrolled identity rather than reinitializing certmesh merely for a
test. Compose Find → Name → Trust → Serve/Pond through real workload/discovery,
DNS/mDNS, current trust diagnosis and certificate paths, health/proxy where supported,
and the narrow peer-read Pond surface; report a genuinely unavailable optional adapter
without disabling independent routes.

Local artifact installation may proceed concurrently across machines; destructive
cross-host provider/network work remains serial and each hat mutates only its own OS.
CachyOS coordinates the shared run IDs after peers publish artifact-ready evidence.
Windows↔Avahi, Windows↔native, and Avahi/resolve1↔native are the minimum provider
rotations. Every participant also proves withdrawal and exact restoration, while each
Pond subject is read from an independent physical host. No second Koi, fake endpoint,
alternate acceptance port, or checkout deployment is permitted.

Evidence-only, harness-only, journal, and dispatcher commits after the freeze do not
move the candidate. Any correction to product code, dependencies, installer/package
recipes, or shipped assets invalidates it: update this section with one new exact SHA,
rebuild every affected artifact, and rerun the affected PH-4 slices. Never silently
test different revisions under the same candidate name. PH-5 starts only after all five
hat journals show the frozen artifact and PH-4 is reconciled green.

### 2026-09-03 08:16 EDT PH-4 convergence dispatch

The final re-freeze remains `5c89e9de11bf23ab81fd8b5b0778c58477359360`.
Windows, Alpine, and Debian have exact-source installed artifacts and green local
journeys. Bluefin's recorded PH-4 artifact came from the invalidated first freeze and
must be rebuilt; CachyOS still owns its exact-source installation/local journey and the
final coordination. The next work is deliberately small and dependency-ready:

1. Bluefin rebuilds and installs the exact re-freeze, repeats its installed local
   journey, and publishes artifact readiness under coordination key
   `ph4-5c89-bluefin-local-02`.
2. Debian keeps its accepted artifact and runs only its missing restoration-gated Pond
   transaction, using CachyOS as the unchanged physical reader under
   `ph4-5c89-debian-pond-01`. An unset convenience environment variable is not a
   credential blocker: use the test-lab credential and pinned host identity already
   recorded in `local/NOTES.md` and `tools/koi-lab/lab.json`, without recording the
   secret or placing it in argv.
3. Windows keeps its accepted artifact and owns the serial Windows↔Alpine/native
   provider transaction `ph4-5c89-win-native-01`. Its driver may create only run-owned
   Koi API traffic on Alpine; all provider/service/profile changes remain Windows-local.
   Alpine stays on its accepted native artifact with Avahi stopped and does not launch
   a competing transaction.
4. CachyOS builds/installs the re-freeze locally, then publishes the remaining shared
   run IDs for Windows↔Avahi and Avahi/resolve1↔Alpine/native. It reconciles PH-4 only
   after Bluefin, Debian Pond, and all provider rotations are green.

These three remote lanes may proceed while CachyOS builds because they do not overlap
system mutations. Every lane ends with exact service/provider/network/firewall/Pond
restoration, one installed Koi, secret-redacted evidence, and a direct push to `dev`.
Do not repeat an already-green local journey or begin PH-5 merely to keep an agent busy.

### 2026-09-03 09:04 EDT PH-4 CachyOS acceptance checkpoint

The final re-freeze remains `5c89e9de11bf23ab81fd8b5b0778c58477359360`.
All five hats now have accepted exact-source artifacts and their completed local-slice
evidence. Bluefin replaced its invalidated build under
`ph4-5c89-bluefin-local-02`, and CachyOS closed its local journey plus Pond run
`20260903T124749Z-924542`. CachyOS also closed
the Avahi/resolve1↔Alpine/native provider lane in
`20260903T125812Z-925941`: the installed systemd and OpenRC processes and hashes stayed
fixed through generations 1–5, bidirectional address/TXT/lifecycle assertions and a
real late resolve1 conflict passed, and both provider baselines restored exactly.

That lane required one harness-only correction so a peer may be attested through
systemd or OpenRC independently of the subject. It does not change product,
dependencies, installers, packages, or shipped assets and therefore does not move the
freeze. The remaining PH-4 critical path is now only:

1. Windows owns serial `ph4-5c89-win-native-01` against unchanged Alpine, followed by
   `ph4-5c89-win-avahi-01` against unchanged CachyOS. It mutates only Windows and proves
   the same bidirectional provider/fallback/withdrawal and restoration contract.
2. Debian owns `ph4-5c89-debian-pond-01` against unchanged CachyOS. Its earlier attempt
   stopped before mutation because the peer credential had not reached that machine;
   it resumes only from an operator-approved private credential handoff.
3. CachyOS reconciles PH-4 green only after those journal entries land and every host
   again reports its exact artifact, singleton deployment, and clean baseline. PH-5
   remains gated until then.

### 2026-09-03 convergence checkpoint

Windows, CachyOS, Bluefin, Debian, and Alpine have closed their current local PH-2/PH-3
physical gates. Alpine has also closed package ownership, transactional OpenRC
supervision, the native musl foundation, and its installed Plasma/session lifecycle.
The two shared
corrections formerly owned by the CachyOS integration driver landed in `41ad76b`:

1. Linux install planning must distinguish the Koi deployment being replaced from a
   genuinely foreign port owner. Systemd and OpenRC must preserve an existing
   explicit or effective port run without manufacturing a shifted configuration,
   while a fresh install must still coexist with a real incumbent.
2. A `systemd-resolved` publication must own conflict observation for its complete
   lease. The initial quiet-settlement window may acknowledge establishment, but a
   later `Conflicted` signal or lost signal channel must invalidate the materialized
   publication and drive ordinary provider reconciliation rather than leave Koi
   reporting a withdrawn record as established.

CachyOS accepted both corrections on its one real deployment: an in-place upgrade
kept `5641:5644` without creating a config, a deliberately unhealthy candidate
restored the exact prior deployment, and physical run
`20260903T000933Z-837819` observed a late resolve1 conflict as
`desired=3, established=1, pending=2` before automatic recovery to `3/3/0`.
The Koi PID stayed fixed and both hosts' provider state was restored exactly.
CachyOS then retained that daemon and its one packaged Plasma workbench through
lock/unlock, primary-interface loss/return, and a real suspend/resume. A fresh
Plasma Login Manager session armed exactly one minimized workbench from its native
package, and an unrelated UID remained outside authenticated local control.

Alpine has also closed its provider/interface recovery gate on the installed OpenRC
service: physical run `20260903T014605Z-1730` held one daemon through
`avahi → native → avahi`, restored installed-but-stopped Avahi, and recovered a
pre-armed primary-interface down/up cycle with bidirectional Debian-peer discovery
and withdrawal. Alpine's local PH-3 gate is also closed: an unrelated UID was denied
at the owner-private socket, and two bounded Debian-origin hostile-input passes left
PID, resources, native routes, and publication state stable while every excluded
Pond/operator route stayed unreachable. Alpine then accepted the ownership-aware
installer on dated APK source `32172ba`: its standing `5651:5654` decision survived
ordinary indexed upgrade, a deliberately unhealthy candidate restored the exact
accepted deployment, and the full locked musl plus physical Debian-peer Pond gates
passed. Alpine's dispatch is complete and its exact installed APK/index are retained
as a PH-4 candidate. Debian accepted the shared installer decision on its one real
deployment. Bluefin's install, rollback, serial real-incumbent, and immutable reboot
activation phases are green. Windows accepted the same final-before-mutation contract
through SCM: its owned no-config deployment retained the standard run, an unhealthy
`StartPending` candidate rolled back exactly after image-verified termination, and a
serial real foreign listener moved a genuinely fresh install to `5651:5654` before
the intended standard deployment was restored without residue.
Debian prepared the reusable PH-5 collector without starting the soak. CachyOS then
accepted the generalized systemd provider and Pond workbooks, reconciled PH-0 through
PH-3, and froze the exact PH-4 source named above.

### Pre-freeze critical path — complete

1. **Fleet PH-1 acceptance closed.** Bluefin, Windows, and Debian published their final
   ownership-aware installed lifecycle verdicts on `dev`; Alpine and CachyOS had
   already accepted the same shared decision.
2. **The integration regression closed.** CachyOS passed the generalized systemd
   provider and corrected Pond workbooks against Bluefin with one installed Koi per
   host and exact restoration.
3. **PH-0 through PH-3 reconciled.** All five hats' public-contract, lifecycle,
   recovery, and adversarial evidence is green; the surface ledger and repository
   contract gates pass.
4. **Freeze handed off to PH-4.** The exact source is named above. Every hat now installs
   its artifact from that revision and owns its system mutations; CachyOS drives the
   serial cross-provider/Pond matrix. The long soak remains gated on PH-4.

## Immediate correctness work

These are observed defects, not speculative framework work.

### Windows

1. `windows_dnsapi.rs::multicast_enabled()` treats `DNSClient\EnableMulticast`
   as mDNS policy. [Microsoft's ADMX mapping](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient#turn_off_multicast)
   documents that value as the LLMNR switch. Remove it as an mDNS fact unless a
   genuine Microsoft mDNS authority is found; assess DNS-SD exports, Dnscache
   availability, and real session operations.
   Require only the exports used by the adapter's read routes.
2. Complete Bonjour read fidelity: retain callback interface/domain identity and
   resolve addresses through the native API. Publication, browse, resolve, removal,
   and teardown remain single-owner and acknowledged.
3. Reconcile the named-pipe DACL and peer authorization contract for the recorded
   operator, SYSTEM, and Administrators while continuing to reject an unrelated user.
4. Make SCM installation transactional and product-owned. Do not register a source
   build path. Binary, service config, operator policy, and exact Koi firewall rules
   roll back together after a failed health check.
5. Pond firewall assessment must include active profile and executable/port filters;
   the existence of a display-name match is not an open-path verdict.

### Alpine

1. Replace the workbench's unconditional Linux `systemctl` calls with one small
   service-manager adapter (`Systemd | OpenRC | Unavailable`) that owns assessment,
   status, start, and stop. `Run once` must recognize either installed manager and
   refuse a second Koi.
2. Use OpenRC's native supervision with bounded respawn and health behavior rather
   than an unsupervised background process, following OpenRC's
   [`supervise-daemon` contract](https://github.com/OpenRC/openrc/blob/master/supervise-daemon-guide.md).
   Start/enable/health failures make `koi install` fail and restore the prior
   installation; success is not a warning.
3. Produce a native package-owned desktop artifact through `abuild`, with canonical
   entry/icon/runtime dependencies and ordinary `apk upgrade` ownership. Acceptance
   never uses the checkout binary.
4. Bound or rotate daemon logs using the platform's native mechanism.

## Hat assignments

### Windows — first-class Windows control plane

- Land the immediate Windows corrections above on current `dev` and install through
  the real product path.
- Close ADR-040 and ADR-042 through the installed service/workbench: pipe DACL and
  wrong-user rejection, shifted endpoint/events/mutations, narrow Pond routes, exact
  firewall applicability, stop, and SCM restart recovery.
- Exercise cooperative DNS against the real port-53 incumbent without changing ICS,
  adapter DNS, or resolver policy to manufacture success.
- Run a single installed-service provider workbook with CachyOS (Avahi) and Alpine
  (native): Windows DNS-SD reads + native publication; verified Bonjour promotion,
  loss/fallback, and restoration; NIC down/up; Public/Private profile facts; lock and
  sleep/resume. Protected Dnscache and LLMNR policy are not test levers.
- Complete desktop install/upgrade/uninstall, fresh login, tray, notification, and
  one-process gates, followed by an installed-product soak.
- Windows local PH-2 gate green on 2026-09-02: one installed candidate retained its PID
  through Windows DNS-SD reads/native publication, verified Bonjour promotion/loss/return,
  Public/Private categories, primary-NIC disable/enable, lock, and real S3 resume while
  unchanged CachyOS/Avahi and Alpine/native peers provided bidirectional publications and
  reads. Provider packages, profile/link state, Dnscache/LLMNR policy, recovery tasks, and
  peer registrations restored exactly.

### Alpine — retainable musl workstation

- Land the OpenRC, installer-truth, desktop service-manager, APK, and log-lifecycle
  corrections above.
- Prove package install/upgrade/uninstall/reinstall, cold boot, supervised SIGKILL
  recovery, fresh Plasma login, one SNI item, notification, lock/unlock, and exact
  service controls.
- Generalize the focused provider gate by provider/service capability, then prove
  Avahi selection when installed, native fallback on Avahi loss, restoration, primary
  interface churn, and suspend/resume against one unchanged physical peer.
- Re-run full native musl gates and Pond after every shared candidate settles.

### CachyOS — Plasma reference and integration driver

- Keep the Arch package lifecycle, native decoration, Plasma tray/notification,
  autostart, and local-control experience as the desktop reference.
- Prove login/lock/suspend/network churn, UFW blocked→open→restored reconciliation,
  Avahi/resolved/native transitions, and wrong-user/Pond negative boundaries.
- Drive the final cross-host provider and Pond gates on the frozen candidate; do not
  absorb another OS's platform logic locally.

### Bluefin — immutable workstation reference

- Prove RPM build, rpm-ostree upgrade and rollback, reboot, one GNOME-autostarted UI,
  SNI reveal, notification, lock/suspend recovery, and removal without layering build
  dependencies onto the host.
- Exercise firewalld applicability and Avahi/resolved/native recovery after interface
  and service churn. Validate shared fixes independently rather than copying Fedora
  behavior into common policy.

### Debian — headless lifecycle and soak anchor

- Repeatedly prove real install → in-place upgrade → failed-upgrade rollback → reboot →
  uninstall → reinstall, including partial-install and corrupted-state diagnostics.
- Exercise every non-desktop capability through CLI/API/Pond with useful headless
  recovery, and act as the stable peer for workstation absence/recovery.
- Host the long mixed-OS soak evidence collector without replacing installed Koi with
  an isolated lab daemon.
- Local PH-2/PH-3 workbook green on 2026-09-02: the one installed service survived
  Avahi/resolved/native loss and return, pre-armed primary-link/address churn, real
  independent-peer Pond allowlist and negative-route checks, and bounded hostile
  DNS/mDNS/HTTP input with stable process/resource bounds. Debian correctly reported
  that neither UFW nor firewalld was active and made no acceptance-only firewall change.

## PH-3 adversarial minimum

- Another ordinary local account cannot cross the Unix socket or named-pipe boundary;
  intended operator/system identities can.
- LAN clients cannot reach operator mutations, excluded Pond reads, OpenAPI, MCP, or
  local-only data through the Pond port.
- Installer rollback cannot weaken ACLs, widen binds, strand firewall rules, replace
  another executable, or report success after a failed start/health check.
- Malformed and hostile mDNS/DNS/HTTP inputs remain bounded and non-fatal; provider
  callbacks cannot outlive reclaimed contexts.
- Secrets never enter argv, journals, evidence bundles, URLs, or public status. Final
  evidence explicitly attests redaction.

## Frozen-candidate exit matrix

PH-4 freezes one `dev` commit after all fixes land. Every host installs an artifact
built from that revision and records source SHA, platform artifact SHA-256, installed
path/owner, service identity, PID, and desktop PID where applicable.

The epic cannot close until:

1. Windows↔Avahi, Windows↔native Koi, and Avahi/resolved↔native Koi prove bidirectional
   publish, browse, resolve, address/TXT/interface data, withdrawal, provider loss, and
   exact restoration through installed Koi APIs.
2. Every advertised capability completes a physical composed journey on its supported
   OS or reports a precise unavailable state without disabling an independent route.
3. Desktop hats pass boot/login, tray, notification, local control, Phone/Pond,
   close/reopen, lock/unlock, suspend/resume, and duplicate-process/item checks.
   Debian passes equivalent boot/operator/Pond checks without a GUI.
4. Install, upgrade, rollback, uninstall, and reinstall use durable product paths on
   every claimed OS. No checkout path survives into a service or login entry.
5. A minimum six-hour soak, with 24 hours required for release-quality evidence,
   samples RSS, handles/descriptors, threads, cache size, provider generations, retry
   rate, desired/established counts, process identity, and cross-host traffic while
   executing controlled faults.
6. Full native gates rerun after the soak; temporary provider, package, firewall,
   resolver, login, network, credential, and test state is absent or byte-exactly
   restored. Each machine retains exactly its intended healthy Koi deployment.

macOS has no physical hat in this fleet. Cross-compilation may remain green, but macOS
must be described as unverified/preview until a real launchd/login/provider lifecycle
meets the same contract.

## Coordination and evidence

Every agent starts with `fleet/task.md`, researches its own OS, fixes shared contracts
at the shared boundary, commits directly to `dev`, rebases on push races, and leaves no
orphan branch or local-only commit. Cross-host system mutations are serial; the host's
own hat owns them. The peer supplies run-owned API traffic and observations.

One meaningful physical run needs one journal entry: PH ID, source/artifact identities,
PIDs, peers/run ID, verdict, important observation, exact restoration result, final
installed state, and fix commit or unresolved issue. Issues are for residue only.
`docs/SURFACES.md` changes when a public claim changes. This epic table changes only
when a whole gate closes.

External signing, registry publication, package-manager submission, tagging, and a
public release remain separate operator-authorized actions. Their absence is reported
truthfully and never papered over with an unsigned-success claim.
