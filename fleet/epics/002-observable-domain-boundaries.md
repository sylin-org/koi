# Epic 002 — Observable domain boundaries

- **Status:** OD-2 complete; OD-3 collectors complete with a Windows resource-gate failure; final Windows process restoration dispatched
- **Opened:** 2026-09-03
- **Decision:** [ADR-043](../../docs/adr/043-observable-domain-boundaries.md)
- **Supersedes as active dispatch:** Epic 001 PH-5 release/soak work

## Objective

Make every Koi domain expose one cheap immutable status snapshot and a coalescing status
subscription, keep commands/state/events distinct, and make certmesh the first complete
authoritative boundary. Move every product presentation and cross-domain consumer to those
boundaries before naming another release candidate. Every observer, provider actor, listener,
connection set, and projector feeding those boundaries must have one explicit lifecycle owner;
partial startup and service installation must roll back as durable transactions rather than
leaving a second, unreported machine state.

The source workspace is `1.0.0-dev.0` for this work. The former frozen source
`e49bfe2b3e403fa87d4b8b237b49f3bb9e5cb5ef` is withdrawn as the active release candidate.
That does **not** erase or reverse Epic 001's accepted PH-4 results: its journals and physical
evidence remain true for the exact artifact tested. They are historical evidence, not proof
for the new development line.

## Dependency map

| Stage | State | Exit |
| --- | --- | --- |
| OD-0 — boundary implementation | **complete at `2f967e4`** | ADR-043 types, feeds, mutation ordering, composition, protected certmesh status/public bootstrap, consumer migrations, lifecycle ownership, and transactional startup/install recovery are complete |
| OD-1 — repository validation | **complete at `2f967e4`** | full locked workspace tests, strict clippy, formatting, architecture/status/security gates, Windows GNU checks, lean embedded builds, TypeScript tests, and documentation checks pass |
| OD-2 — focused native validation | **complete; 5/5 hats accepted 2026-09-04** | every hat closed its row below using one installed Koi and at least one independent physical peer |
| OD-3 — candidate matrix and soak | **collector campaign complete; FAIL at frozen `b3eb47e`; Windows restoration follow-up active** | preserve the failed verdict, return the Windows installed process to its bounded baseline, then close the campaign without rerunning the soak |

## Current fleet dispatch — 2026-09-04 OD-2

This section outranks retained PH-5 sections in every hat brief.

`e64b50e` is the current OD-2 product baseline, not a frozen release candidate. Its change after
the Windows/CachyOS accepted product tree is isolated to the OpenRC installer, so it does not
invalidate those completed systemd/SCM rows; Alpine must exercise it. Pull the latest `dev`
before starting; documentation-only commits do not invalidate product evidence. A product,
dependency, installer, package, or shipped-asset correction creates a new baseline: its owner
tests and pushes it directly, and any hat whose uncompleted row is affected synchronizes before
claiming a pass. Historical evidence remains true only for its recorded source and artifact.

Every hat may research locally, in repository history, and online; install the dependencies
needed by its own OS; and exercise its own provider, service manager, firewall, session, and
network state under the protocol's capture-and-restore rules. Use the real deployment and real
endpoints. There is exactly one installed Koi per host; no alternate-port twin, isolated data
root, fake production capability, or second helper daemon can satisfy a gate.

| Hat | Owned OD-2 delivery | Required physical proof |
| --- | --- | --- |
| `cachyos-linux` | **Complete 2026-09-04.** The accepted Pond gate plus exact merged-tree systemd collector and Avahi/resolve1/native slices close this row. No further local mutation is assigned unless an affecting product change lands. | Provider run `20260904T133043Z-1223793` kept PID/hash fixed through generations `6→34`, real bidirectional peer traffic, conflict recovery, and exact provider restoration. Collector run `v1-20260904T133355Z-cachyos` captured seven healthy aggregate/peer samples with zero retry, restart, unavailable sample, or resource-threshold failure; Bluefin Pond and both hosts were restored exactly. |
| `windows` | **Complete 2026-09-04.** The real SCM observer, transactional installed service, authenticated named-pipe lifecycle/DACL, HostIdentity, and Windows DNS-SD/Bonjour/native provider slices are accepted. No further local mutation is assigned unless an affecting product change lands. | Provider run `od2-9d-win-avahi-01` kept the one SCM PID/hash fixed across native, Bonjour promotion/loss/return, and restoration while exchanging real records with CachyOS. Collector run `v1-20260904T134802Z-windows-scm` passed all 14 checks and 7/7 Bluefin Pond reads; an unrelated unelevated SID was denied at the pipe, and all service/provider/firewall/peer state was restored. |
| `alpine-linux` | **Complete 2026-09-04.** The real OpenRC observer, exact musl packages, package-replacement-aware transactional install, local IPC/HostIdentity, and Avahi/native behavior are accepted. No further local mutation is assigned unless an affecting product change lands. | Provider run `20260904T140752Z-28808` kept PID/hash fixed through generations `14→18→22`, bidirectional test-01 traffic, withdrawal, and exact Avahi restoration. Collector run `v1-20260904T1413Z-alpine-od2` passed all 14 checks with 7/7 physical Bluefin Pond reads, zero retries/restarts/unavailable samples, revision convergence, and bounded resources; restart reconstruction, unrelated-UID denial, and exact host/peer restoration passed. |
| `bluefin-linux` | **Complete 2026-09-04.** The exact published-tree systemd deployment, authenticated local IPC/HostIdentity, status/inventory/Pond projections, and Avahi/resolve1/native transitions are accepted. No further local mutation is assigned unless an affecting product change lands. | Provider run `20260904T132001Z-205263` kept PID/hash fixed through generations `6→31`, real bidirectional test-01 traffic, conflict recovery, and exact provider restoration. Pond run `20260904T132300Z-207507` proved the physical allowlist and restart reconstruction. Collector run `v1-20260904T1503Z-bluefin-od2` passed all 14 checks with 7/7 physical Alpine Pond reads, zero retry/restart/unavailable sample, converged publications, and bounded resources; both hosts were restored exactly. |
| `debian-linux` | **Complete 2026-09-04.** The synchronized headless systemd deployment, neutral CLI local control, aggregate status/inventory/Pond projections, HostIdentity, restart reconstruction, and neutral systemd observer are accepted. No further local mutation is assigned until OD-3 names the frozen source. | Pond run `20260904T154318Z-50711` proved the physical allowlist, generation retention, stop/restart reconstruction, and exact restoration against test-01. Collector run `v1-od2-e64-debian-systemd-canary-02` passed all 14 checks with 7/7 physical peer Pond reads, zero retry/restart/unavailable sample, revision convergence, and bounded resources; both hosts were restored exactly. |

Cross-host evidence is coordinated, not simulated: use a shared run ID and retain both machines'
source/artifact hash, service identity/PID, status revision/provider generation, traffic result,
and restoration verdict. A hat owns mutations on its own host. The peer may perform run-owned Koi
API publications and reads; provider, firewall, package, service, and session mutation requires
the peer hat. Prefer available stable pairs (`Windows↔Alpine`, `Bluefin↔CachyOS`, and
`Debian↔CachyOS/Bluefin`), but agents may choose another available fleet peer when that produces
the same real assertion without waiting.

Do not add a framework merely to coordinate the run. The cheap boundary snapshot, its coalescing
change feed, the real native adapter, and an evidence-producing client are the meaningful pieces.
If a native observer is absent, implement it; do not expose a guessed state. If a defect is found,
fix it at the responsible boundary, add the smallest regression coverage, push it, and continue
the physical gate on the corrected source. Add an ADR only when the architecture decision changes.

A row closes only with a journal entry and direct push containing exact provenance, the real
cross-host assertion, the short native collector result, and exact final restoration. Once all
five rows close, update this epic once to dispatch OD-3; do not start the long soak independently.

## OD-3 dispatch — frozen candidate and one native-manager soak

The exact frozen source is
`b3eb47e08817045f9371703d780ada9aab00995d`. It contains the final Debian OD-2
acceptance and Alpine package recipe; its shipped product tree is still the accepted
`e64b50e` baseline. Documentation/evidence commits after the freeze do not invalidate it.
Any product, dependency, installer, package-recipe, or shipped-asset change does: stop the
affected matrix/soak slice, fix and validate it at its owning boundary, then have CachyOS
publish a replacement freeze. Never build a candidate from later `dev` and label it with
the frozen SHA.

The shared campaign ID is `v1-20260904-od3-b3eb47e`. First close the deliberately small
candidate matrix below. This is artifact/readiness reconciliation, not permission to repeat
OD-2's already-green provider, Pond, firewall, security, or workstation gates.

| Hat | Frozen-candidate work | State |
| --- | --- | --- |
| `cachyos-linux` | Build `koi` and `koi-lab` from a clean export/detached worktree of the frozen source; install the exact `koi` serially through the product installer; prove one enabled/healthy systemd service, authenticated aggregate/provider/publication truth, exact installed hash, and a short systemd collector against a physical Koi Pond peer; restore the peer. | **READY 2026-09-04** — exact installed SHA-256 `b2079cd3…cdc3`; systemd run `v1-20260904-od3-b3eb47e-cac2` passed 14/14 with 7/7 Bluefin Pond reads and exact peer restoration |
| `bluefin-linux` | Repeat the same exact-source serial install and short systemd readiness/collector proof. Its prior installed binary predates the frozen Linux product tree. Restore its service, Pond desire, firewall, and desktop baseline exactly. | **READY 2026-09-04** — frozen artifact `ddf603d7…a6c3` is installed as the sole active/enabled systemd service at PID `258776`; readiness collector `v1-20260904-od3-b3eb47e-bluefin-ready` passed 14/14 with 7/7 Alpine Pond reads and exact peer/baseline restoration |
| `windows` | Build the frozen Windows artifacts and compare them with the accepted installed artifact. Because changes since its accepted product tree are Linux OpenRC/test/docs only, do not replace or repeat SCM/provider/DACL gates when bytes are identical. If bytes differ, serially install and run only the short SCM collector/readiness proof. | **READY 2026-09-04** — exact installed SHA-256 `d47138c5…7610`; SCM run `v1-od3-win-20260904T163240Z` passed 14/14 with 7/7 Bluefin Pond reads and exact peer restoration |
| `alpine-linux` | Verify the installed APKs, payload hashes, recipe source pin, service identity, and aggregate/provider readiness against the frozen source. The exact `e64b50e` product and final recipe are already installed/accepted; do not rebuild or repeat destructive gates unless equivalence fails. | **READY 2026-09-04** — installed APK payload SHA-256 `a713968f…a5e6`, frozen recipe/pin and retained signed package hashes exact, one healthy OpenRC child PID `31872`, native publications `1/1/0/0`, no mutation |
| `debian-linux` | Verify the installed binary/product-tree equivalence, systemd identity, and aggregate/provider readiness against the frozen source. The exact `e64b50e` product is already installed/accepted; do not repeat the just-completed Pond/collector gates unless equivalence fails. | **READY 2026-09-04** — installed/retained release SHA-256 `899d83ef…a1cc`, one healthy systemd PID `50905`, Avahi publications `1/1/0/0`, no mutation |

All five hats are ready. The coordinated soak uses `T0=2026-09-04T17:30:00Z` and targets
completion at `2026-09-04T23:30:00Z`; collectors may finish slightly later because their
six-hour duration starts when each process actually enters sampling. This scheduled run is
the active task for every hat below. Pull the dispatch and perform the owned preflight now;
do not report `no task` because the candidate row is complete or an older brief says to wait.

The one soak lasts six hours with 60-second samples. It uses the real installed observers and
one stable physical Bluefin Pond surface: Windows runs SCM collector
`v1-20260904-od3-b3eb47e-win`, Alpine runs OpenRC collector
`v1-20260904-od3-b3eb47e-alp`, and Debian runs systemd collector
`v1-20260904-od3-b3eb47e-deb`. Bluefin owns arming/restoring its persisted Pond desire and
any host firewall state; it performs no scheduled service fault. Observer thresholds are one
expected service restart, at most two unavailable samples with no more than two consecutive,
and the collector's default bounded resource-growth limits.

Faults are serial and owned by the affected hat: Windows restarts its SCM service at `T0+60m`,
Alpine restarts its OpenRC service at `T0+150m`, and Debian restarts its systemd service at
`T0+240m`. Each verifies a new native PID plus aggregate/provider/publication recovery before
the next window. The final two hours observe recovered steady state. CachyOS owns the shared
timeline and final reconciliation, but runs no second Koi and invents no coordinator service.
All three collectors must complete, make real reads from Bluefin on every sample, remain within
their thresholds, and finish healthy. Bluefin then restores its exact pre-run Pond/firewall
state; every hat records final service/artifact identity and pushes evidence. CachyOS closes
OD-3 only after reconciling all four journals and the three canonical collector verdicts.

| Hat | Active scheduled assignment |
| --- | --- |
| `bluefin-linux` | Capture exact service/artifact/Pond/firewalld baseline now. At `2026-09-04T17:25:00Z`, arm the installed Pond surface returned by Koi and prove it reachable at `192.168.1.95:5644`. Keep it stable until all three collectors finish; then stop sharing, prove the listener closed, restore exact firewall/Pond/service state, journal, and push. Do not restart Koi during the run. |
| `windows` | Capture exact SCM/artifact/provider baseline and stage bounded local recovery now. At or immediately after `T0`, run the frozen `koi-lab.exe installed-service-collect` for 21,600 seconds with 60-second samples, observer `windows-scm`, service `koi`, binary `C:\Program Files\Koi\koi.exe`, run ID `v1-20260904-od3-b3eb47e-win`, Bluefin peer label/surface, and the published thresholds. Restart only the SCM Koi service at `2026-09-04T18:30:00Z`; remove scheduling/recovery residue, journal the canonical verdict and exact restoration, and push. |
| `alpine-linux` | Capture exact OpenRC/APK/provider baseline and stage bounded local recovery now. At or immediately after `T0`, run the frozen `koi-lab installed-service-collect` for 21,600 seconds with 60-second samples, observer `openrc`, service `koi`, binary `/usr/bin/koi`, run ID `v1-20260904-od3-b3eb47e-alp`, Bluefin peer label/surface, and the published thresholds. Restart only the OpenRC Koi service at `2026-09-04T20:00:00Z`; remove scheduling/recovery residue, journal the canonical verdict and exact restoration, and push. |
| `debian-linux` | Capture exact systemd/artifact/provider baseline and stage bounded local recovery now. At or immediately after `T0`, run the frozen `koi-lab installed-service-collect` for 21,600 seconds with 60-second samples, observer `systemd`, service `koi.service`, binary `/usr/local/bin/koi`, run ID `v1-20260904-od3-b3eb47e-deb`, Bluefin peer label/surface, and the published thresholds. Restart only `koi.service` at `2026-09-04T21:30:00Z`; remove scheduling/recovery residue, journal the canonical verdict and exact restoration, and push. |
| `cachyos-linux` | Own the UTC timeline. Before `T0`, verify all hats remain on their recorded candidate identity and Bluefin Pond is physically reachable. During the run, observe the shared branch and Bluefin surface without starting another Koi or mutating another host. After all three collector entries and Bluefin restoration land, reconcile exact source/artifact/PID/restart/traffic/resource/restoration verdicts, close or precisely redispatch OD-3, and push. |

For every collector invocation pass `--max-service-restarts 1`,
`--max-unavailable-samples 2`, and `--max-consecutive-unavailable-samples 2`; retain the
default resource-growth bounds. Launch the collector from the clean frozen worktree/export so
its `source_commit` is exactly `b3eb47e08817045f9371703d780ada9aab00995d`. Use a native
scheduled task/timer or a second owned shell for the timed restart while the collector remains
foregrounded; the timing mechanism is run residue and must be removed. A late start does not
compress six hours or move a fault earlier: perform a missed scheduled fault immediately after
sampling begins, record the lateness, and retain the remaining serial order.

## OD-3 reconciliation — 2026-09-04

The coordinated run is complete and its canonical verdict is **FAIL**. Debian and
Alpine passed all 14 checks across 361 samples apiece, including their one planned
native-manager PID transition, bounded resources, 361/361 physical Bluefin reads,
and exact cleanup. Bluefin remained stable for all 1,083 collector reads and restored
its persisted Pond desire, listener, firewall, service, and run residue exactly.

Windows passed 12/14 checks and all 361 physical peer reads, but handles grew
`+1329` against a limit of 16 and threads grew `+280` against a limit of 8. The
installed service stayed healthy on the frozen artifact and all scheduled-task,
configuration, policy, Pond, Bonjour, detached-worktree, and second-process cleanup
passed. Its final live process nevertheless remained at elevated resource counts, so
that host did not make an exact green restoration claim. Issue
[004](../windows/issues/004-windows-dnsapi-meta-browse-resource-growth.md) diagnoses
the product defect: the Windows DNSAPI adapter forwards unrelated PTR owners from a
query result, false service types accumulate, and the dashboard starts one native
browse worker per false type. The failed candidate is rejected and must not be
relabeled or reused.

The only active Epic 002 work is this bounded Windows-owned restoration, resumed as
the cleanup tail of the already authorized run:

1. capture the current SCM descriptor, installed SHA-256, workbench identity,
   provider/publication state, Pond state, and live handle/thread counts;
2. restart only the existing `koi` SCM service once—no build, install, provider,
   firewall, configuration, workbench, peer, or source mutation;
3. over two one-minute observations, require exactly one healthy AutoStart service,
   the same frozen installed hash, authenticated control, concrete DNS-SD routes,
   converged `1/1/0/0` publications, disabled Pond, and process resources returned
   to the recorded post-restart envelope (no more than 364 handles and 75 threads);
4. record the final PID/counters and absence of recovery or scheduling residue in the
   Windows journal and push it directly to `dev`.

This is restoration evidence, not a corrected-candidate test. Do not run another
six-hour soak or implement issue 004 under Epic 002. After that one journal entry
lands, CachyOS closes Epic 002 as an unsuccessful candidate campaign, accepts R01's
handover, and assigns the product correction to Epic 003 R03. If the reset cannot
meet the envelope, preserve the exact measurements and keep the handover pending;
do not raise the limits.

## Validation contract for OD-0/OD-1

Repository validation must establish:

1. every domain returns its current immutable status without I/O/await/lock exposure and a
   new watcher sees that value immediately;
2. revisions advance on semantic changes, no-ops do not wake watchers, and coalesced/lagged
   consumers converge by rereading current state;
3. durable mutations publish in commit → status → event order and failure leaks neither a
   proposed success snapshot nor event;
4. certmesh distinguishes role, membership, authority, and identity health; a joined but
   damaged identity remains enforcement-closed;
5. full certmesh status is protected while the public bootstrap projection is minimal and
   sufficient for pinned enrollment;
6. `KoiStatusRuntime` owns the instance-scoped `KoiStatus` aggregate and explicit composition
   inputs without a global note registry; HTTP, dashboard, MCP, CLI, embedded, and Pond
   projections consume that aggregate; and
7. architecture guards preserve dependency direction, domain persistence ownership, and the
   `mdns-sd` boundary;
8. restartable stop and terminal shutdown remain distinct; after admission either transition
   converges through its owned cancel/abort/reap tail even when the requester disappears, with
   later calls sharing completion rather than being required for progress; Drop fences live
   work; and listener/provider/session children drain or abort within one bounded deadline
   without persistent Arc self-cycles, including on panic;
9. process-derived announcements are session-owned, provider transitions are
   break-before-make, and failed withdrawal/replacement converges without a duplicate or a
   permanent stale registration; and
10. systemd, OpenRC, and Windows installation serialize through one machine-global lock and
    recover only integrity-validated, durably checkpointed transactions; fault-injection and
    race tests prove no-clobber backup creation and cleanup-only recovery after the semantic
    commit;
11. cancellation before command admission has no effect, while cancellation after admission
    cannot split durable/native truth from the in-memory model, specialized projections, primary
    status, or success event; blocking platform work is queue-bounded, domain-owned, drained, and
    joined; and
12. Runtime-derived DNS, Health, and Proxy state is applied as complete transient scoped desired
    sets, never persisted as operator configuration or tracked in a composition-owned inventory;
    restart reconstructs it from current Runtime status and operator configuration wins explicit
    collisions;
13. one `CoreSpec.data_dir` becomes explicit `PersistencePaths` at composition and every domain
    receives only its owned path values; two-root tests prove no state, transition log, or
    certificate-directory crossover and no domain consults an ambient process root;
14. HTTP, IPC, mTLS, and ACME report ready only after exact listeners are acquired; breadcrumbs,
    Windows SCM-running state, and discovery presence follow those fences, while partial binds,
    half-open handshakes, cancellation, and late exits release or reconcile the whole owned
    generation;
15. command mode selection is client-only by default, standalone composition is explicit and
    refused beside a live local service, redirected stdin cannot create a responder, and every
    standalone native resource stays owned for its complete declared lifetime; and
16. custom Runtime producers enter through `RuntimeBackend` with the normal initial snapshot,
    observation, reconciliation, and teardown contract; malformed daemon responses, unavailable
    remote embedded operations, and host-observation failures remain typed errors rather than
    empty/default/no-op state.

## Coordination and publication

The fleet protocol remains one shared `dev` branch with direct authenticated pushes by every
agent that owns an explicitly dispatched change. There is no patch-harvesting, alternate branch,
or local-only completion workflow. Rebase ordinary races, never force-push, and leave a completed
session present on `origin/dev`.
