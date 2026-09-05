# Epic 003 task ledger

This is the single task-status authority for [Epic 003](../../../fleet/epics/003-delight-realignment.md).
All rows are queued at creation. No implementation or native validation is implied.

## Dispatch state

- Campaign: active.
- Universal entry: [fleet/task.md](../../../fleet/task.md), routed through
  [Linux dispatch](../../../fleet/delight-dispatch.md).
- Authorization: owner delegated execution to the Linux machines on 2026-09-04.
- Handover: R01 accepted after Windows restoration at `b18302b`; Epic 002 closed with its failed OD-3 verdict preserved.
- Product implementation: eligible fixed-owner tasks may proceed; no new routine approval required.
- Active candidate: none; Epic 002's frozen candidate is rejected.
- Windows physical evidence: reserved for a later operator-dispatched Windows session.
- Current dispatch: R02/R03/R04/R05/R20 and R28 are accepted. R05 is complete at Koi
  `e673af6` and desktop `ba39faf`; Windows installed proof and complete hosted CI
  `33974240044` pass. R20 is complete at `3eb1147`; all 13 jobs in hosted CI
  `33987878995` pass. CachyOS R06 is dependency-ready. Windows has no further
  dependency-ready source row and next services any ready native-evidence request.
- Capacity constraint (owner instruction, 2026-09-04): Debian is a very weak thin
  client. Preserve its current R03 claim through its small documentation handoff;
  R04/R05 are now reassigned to Windows. Before any later heavy Debian row is
  claimed, CachyOS must split or reassign it. Do not assign full builds, test matrices or stress
  workloads to Debian. See [fleet capacity guidance](../../../fleet/coordination.md#debian-capacity-constraint--owner-instruction-2026-09-04).
- Capacity preference: Windows is the most powerful fleet machine; prefer it for
  compatible heavy assignments when dispatched. Linux-specific evidence remains
  with appropriate Linux executors. Current claims are preserved until handoff.

## Coordinator handoff — 2026-09-05

The owner directed the paused fleet to proceed. R28's source changes are published
and its remaining work is hosted-result reconciliation. CachyOS releases R28's
blanket CONTRACT.md/LEDGER.md write reservation now; acceptance remains pending
until the complete required CI run passes. Shared-file ownership is separate from
task acceptance. This supersedes earlier report instructions coupling both waits.

The bounded write order is:

1. Bluefin owns the next CONTRACT.md edit: only R02's D01/D02/D03/D06/D09/D10
   dispositions. Its implementation and source checks are already published at
   `299ae89`. Finish these rows, verify docs, publish the report/status and explicitly
   release the file to Debian. No repeated build is required for this prose change.
2. Debian may immediately reconcile Windows journal entry 26 at `189ea32` in its
   own R03 report and close the addressed evidence request. After Bluefin releases
   CONTRACT.md, update R03's mDNS observation/source and D04 rows, verify docs and
   promote R03 only when its actual acceptance cases are covered. Windows native
   proof is now published; do not repeat the physical run or full build on Debian.
3. Windows owns R04, then R05, when their prerequisites are accepted. These were
   unclaimed queued rows, so no implementation transfer is needed. On its next
   operator invocation, `fleet/task.md` routes Windows to these source tasks after
   any ready native-proof request. Claim exact files before implementation. Request
   Linux checks from CachyOS/Bluefin or hosted CI using the published source; required
   Linux evidence remains a readiness condition. Debian does not build these tasks.
4. CachyOS owns the R28 cross-host fixture correction and final reconciliation.
   Run `33945321135`, source `1f65a0f4bebd7b485914660c70f11f7123b4aa66`, passed all
   twelve preceding jobs but failed cross-host because its Alpine containers lack
   the machine ID required by the enabled vault backend. The bounded correction
   claim and verification plan are in the R28 report. Replacement run `33946904793`
   passed all 13 jobs on `aa229ea0604cadd7a7d36d81e7f107716dbc686f`; CachyOS has
   accepted R28. This accepts CI infrastructure only; R29 requires fresh candidate
   evidence after subsequent product changes.

Do not launch another host's agent from this dispatch. Each participating operator
session resumes through the same `fleet/task.md` entry. Any CI correction that
needs an occupied shared file must make a new bounded claim rather than restoring
the blanket reservation. Keep all required gates and source identities intact.

## Status and selection rules

Use queued, in_progress, implemented, accepted, or blocked.

- queued: not started, regardless of whether dependencies are ready.
- in_progress: coherent work is underway or checkpointed.
- implemented: code/docs landed locally or by the authorized publication path;
  one or more required external/native/hosted acceptance checks remain.
- accepted: all required cases for this row passed with linked evidence.
- blocked: a specific unavailable input/authority/external dependency prevents the
  next action; record that action and dependency in the report.

Select only the fixed owner's earliest eligible task/slice. Dependencies normally
require accepted status; the narrowly defined Linux readiness exception below
allows implementation without claiming Windows proof. R01 must be accepted,
including inherited-run disposition and the product contract, before any product
task proceeds. Do not accept it solely because the design portion is written.

## Dependency readiness for the Linux delegation

Status records acceptance; Readiness records whether a dependent may start.

- `pending`: not ready for dependents.
- `ready`: accepted with all required evidence and published source.
- `linux-ready`: implemented and published; only explicitly listed Windows
  physical evidence (direct or inherited from dependencies) remains outstanding.

An owner may set linux-ready only when all code/contracts, meaningful source and
hosted checks required by that task, and every required Linux/native/second-peer
case have passed. Record each missing Windows case and its future Windows task
in the selected report. Retain Windows build/API compatibility checks where
available; an uncompiled changed Windows path or failing Windows build is not
"only missing physical evidence". It stays pending until a real target build
succeeds, locally or in hosted CI. No unsupported implementation placeholder,
missing Linux platform proof, missing client TLS check, unresolved security test,
failed required CI, or missing user study qualifies for this exception.

A Linux dependent can consume ready or linux-ready prerequisites when its report
cites their exact published revisions, needed contracts and inherited Windows
cases. It must add its own affected Windows cases and remain implemented/linux-ready
until those obligations are satisfied; the exception cannot disappear downstream.
A parent rolls up only when all required subrows reach the applicable readiness.
Only the parent owner changes its aggregate row; subrow owners update their own rows.

R01 always requires ready. R29's four Linux rows may use linux-ready predecessors
for a clearly labeled Linux development candidate; required Linux and hosted gates
must already pass. R29/windows, R29/reconciliation, R30, all epic-gate acceptance
and every full release verdict require complete acceptance. Those cannot consume
the exception. Windows proof also revisits earlier pending cases (R12,
R16/windows, R17/windows-firewall and affected shared UI/journey rows); the exact
candidate must satisfy them before their owners promote acceptance.

No readiness flag means success by elapsed time or by source changes alone.
Changed contracts invalidate dependent readiness and affected evidence explicitly.

For a task with subrows, choose one ready row applicable to the current executor
and host. All parent dependencies apply to every subrow; additional internal
dependencies are below. Task-level acceptance cases are the union across slices.
Execute the cases relevant to this slice and mark the rest pending; do not repeat
other accepted slices unless a changed contract invalidates them. The parent is
accepted only after all required slices are accepted.

Record source revisions or explicit worktree/diff identity and test commands in
reports/Rxx.md or reports/Rxx-subrow.md. Native evidence remains in owned hat journals;
link it here instead of copying host state into a second ledger. Do not create
reports full of placeholder PASS results. R29 reconciliation owns final candidate
identity and complete hosted/native evidence, even if infrastructure tasks passed earlier.

## Work orders

| ID | Dependencies | Status | Readiness | Owner | Evidence/report | Next action |
|---|---|---|---|---|---|---|
| [R01](R01-contract-and-handover.md) | - | accepted | ready | cachyos-linux | [reports/R01.md](reports/R01.md) | Complete; contract and inherited-run restoration verified |
| [R02](R02-critical-documentation-truth.md) | R01 | accepted | ready | bluefin-linux | [reports/R02.md](reports/R02.md) | Complete on implementation source `299ae89`; six finding dispositions published and CONTRACT/LEDGER reservation released to Debian for R03 |
| [R03](R03-discovery-record-correctness.md) | R01 | accepted | ready | debian-linux | [reports/R03.md](reports/R03.md) | Complete at source `d48d4df`; contract rows and Windows native proof `189ea32` reconciled |
| [R04](R04-service-catalog.md) | R01, R03 | accepted | ready | windows | [reports/R04.md](reports/R04.md) | Source `b822811`; Windows installed-service run passes; CI `33949639819` supplies green Ubuntu workspace plus macOS and contract jobs |
| [R05](R05-catalog-api-and-preferences.md) | R04 | accepted | ready | windows | [reports/R05.md](reports/R05.md) | Koi `e673af6`, desktop `ba39faf`, Windows installed service/workbench run and complete hosted CI `33974240044` pass; complete and R06 unblocked |
| [R06](R06-rust-ui-and-family-foundation.md) | R01, R05 | queued | pending | cachyos-linux | - | See required subrows below |
| [R07](R07-home-launchpad.md) | R05, R06 | queued | pending | cachyos-linux | - | Wait for dependencies |
| [R08](R08-devices-and-comparison.md) | R07 | queued | pending | cachyos-linux | - | Wait for dependencies |
| [R09](R09-settings-about-and-surface-consolidation.md) | R08 | queued | pending | cachyos-linux | - | Wait for dependencies |
| [R10](R10-meaningful-activity.md) | R07 | queued | pending | cachyos-linux | - | Wait for dependencies |
| [R11](R11-installation-contract.md) | R01, R06 | queued | pending | alpine-linux | - | See required subrows below |
| [R12](R12-windows-installation.md) | R11, R09 | queued | pending | bluefin-linux | - | Linux source preparation; Windows physical evidence reserved |
| [R13](R13-linux-installation.md) | R11, R09 | queued | pending | alpine-linux | - | See required subrows below |
| [R14](R14-automatic-second-machine.md) | R03, R07, R12, R13 | queued | pending | debian-linux | - | Wait for dependencies |
| [R15](R15-container-ready-service.md) | R05, R07, R11 | queued | pending | bluefin-linux | - | Wait for dependencies |
| [R16](R16-local-service-detection.md) | R04, R11 | queued | pending | debian-linux | - | See required subrows below |
| [R17](R17-reversible-service-sharing.md) | R05, R11, R16 | queued | pending | debian-linux | - | See required subrows below |
| [R18](R18-share-service-experience.md) | R07, R16, R17 | queued | pending | cachyos-linux | - | Wait for dependencies |
| [R19](R19-url-diagnosis.md) | R04, R07 | queued | pending | debian-linux | - | Wait for dependencies |
| [R20](R20-authorized-service-certificates.md) | R01, R04 | accepted | ready | windows | [reports/R20.md](reports/R20.md) | Source `3eb1147`; exact service-name grant, atomic host leaf lifecycle, account-bound single-name ACME authorization and all 13 hosted CI jobs `33987878995` pass |
| [R21](R21-secure-service-operation.md) | R11, R19, R20 | queued | pending | debian-linux | - | See required subrows below |
| [R22](R22-secure-access-and-client-onboarding.md) | R07, R15, R21 | queued | pending | cachyos-linux | - | See required subrows below |
| [R23](R23-renewal-and-recovery.md) | R21, R22 | queued | pending | debian-linux | - | Wait for dependencies |
| [R24](R24-finished-acme-integration.md) | R20, R22 | queued | pending | bluefin-linux | - | Wait for dependencies |
| [R25](R25-developer-and-agent-experience.md) | R05, R17, R19, R21 | queued | pending | alpine-linux | - | See required subrows below |
| [R26](R26-documentation-and-contributor-path.md) | R02, R09, R14, R15, R18, R22, R23, R24, R25 | queued | pending | bluefin-linux | - | Wait for dependencies |
| [R27](R27-accessibility-and-interaction-proof.md) | R09, R10, R18, R22 | queued | pending | cachyos-linux | - | Wait for dependencies |
| [R28](R28-ci-and-release-contracts.md) | R01 | accepted | ready | alpine-linux | [reports/R28.md](reports/R28.md) | CachyOS reconciled run 33946904793: all 13 jobs passed on `aa229ea`; CI infrastructure accepted, fresh candidate proof remains R29 |
| [R29](R29-candidate-fleet-acceptance.md) | R02, R03, R09, R10, R12, R13, R14, R15, R18, R23, R24, R25, R26, R27, R28 | queued | pending | cachyos-linux | - | See required subrows below |
| [R30](R30-usability-and-release-review.md) | R29 | queued | pending | cachyos-linux | - | Wait for dependencies |

## Bounded subrows

Owners below are fixed dispatch assignments, not an instruction to spawn agents.
One iteration executes one row. Claim exact write paths through the Linux dispatch
before editing. Native evidence stays with the actual hat even when source preparation
has a Linux owner. R12, R16/windows and R17/windows-firewall assign source work to
Bluefin; Windows physical cases remain pending for the Windows hat.

| Slice | Additional prerequisite | Owner | Status | Readiness | Deliverable | Evidence |
|---|---|---|---|---|---|---|
| R06/renderer-decision | - | cachyos-linux | in_progress | pending | All three native compiler targets pass; packaged CachyOS Maud/Tauri live/offline/focus/tray/unavailable proof passes; peer packaged proof and decision pending | [report](reports/R06-renderer-decision.md) |
| R06/shared-shell | R06/renderer-decision | cachyos-linux | queued | pending | Selected reusable shell/assets/data adapter; no remaining production spike variant | - |
| R11/result-contract | - | alpine-linux | queued | pending | Typed install result, artifact compatibility, durable recipe/receipt ownership | - |
| R11/restart-and-rollback | R11/result-contract | alpine-linux | queued | pending | Interrupted install/upgrade recovery, idempotency and old-state preservation | - |
| R13/systemd-plasma | - | cachyos-linux | queued | pending | Installed systemd/glibc Plasma journey including package/login/rollback | - |
| R13/rpm-ostree-gnome | - | bluefin-linux | queued | pending | Immutable native RPM/layer/reboot/session/rollback journey | - |
| R13/openrc-musl | - | alpine-linux | queued | pending | OpenRC/musl package/UI/startup and rollback journey | - |
| R13/systemd-headless | - | debian-linux | queued | pending | No-GUI systemd install/operator/upgrade/rollback journey | - |
| R16/contract | - | debian-linux | queued | pending | Typed candidate/evidence projection, scan limits, mock adapter fixtures | - |
| R16/windows | R16/contract | bluefin-linux | queued | pending | Native Windows listener/process/runtime observation; no mutation | - |
| R16/linux | R16/contract | debian-linux | queued | pending | Native Linux listener/runtime observation with permission fallback; no mutation | - |
| R17/intent-contract | - | debian-linux | queued | pending | Durable intent/receipt, scoped resource IDs, admission/stop/error contract | - |
| R17/routing-and-names | R17/intent-contract | debian-linux | queued | pending | Loopback forwarder, real alias resolution and conflict handling | - |
| R17/windows-firewall | R17/routing-and-names | bluefin-linux | queued | pending | Scoped Windows native rules with durable ownership and idempotent reversal | - |
| R17/linux-firewall | R17/routing-and-names | alpine-linux | queued | pending | Applicable native Linux firewall adapters and precise unsupported/policy-denied results | - |
| R17/recovery-proof | R17/windows-firewall, R17/linux-firewall | debian-linux | queued | pending | Full share crash/restart/stop/cleanup proof across the integrated adapters | - |
| R21/operation-contract | - | debian-linux | queued | pending | Typed progress and durable resource intent over existing domain commands | - |
| R21/domain-composition | R21/operation-contract | debian-linux | queued | pending | Actual name/grant/leaf/listener/backend integration and client prerequisite output | - |
| R21/recovery-proof | R21/domain-composition | debian-linux | queued | pending | Cancellation/restart/conflict/cleanup proof and existing-resource reuse | - |
| R22/creation-and-joining | - | debian-linux | queued | pending | Simple create/invite/join language and any justified ceremony ADR amendment | - |
| R22/service-setup-ui | R22/creation-and-joining | cachyos-linux | queued | pending | Live secure-service progress/retry/reopen flow with contextual details | - |
| R22/client-verification | R22/service-setup-ui | bluefin-linux | queued | pending | Public client setup bundle and real named second-client/container HTTPS proof | - |
| R25/cli-rust-client | - | alpine-linux | queued | pending | Stable task commands, transport/errors, help and human/JSON behavior | - |
| R25/typescript-python | R25/cli-rust-client | bluefin-linux | queued | pending | Both existing thin SDKs, compatibility/negative fixtures and minimal recipes | - |
| R25/mcp | R25/cli-rust-client | alpine-linux | queued | pending | Permitted service tasks and one actual named-client recipe | - |
| R25/embedded | R25/cli-rust-client | alpine-linux | queued | pending | Shared lifecycle facade, external lean example and orderly shutdown | - |
| R29/windows | - | windows | queued | pending | Exact-candidate Windows native/journey/soak obligations | - |
| R29/cachyos-linux | - | cachyos-linux | queued | pending | Exact-candidate glibc Plasma native/journey/soak obligations | - |
| R29/bluefin-linux | - | bluefin-linux | queued | pending | Exact-candidate immutable GNOME native/journey/peer obligations | - |
| R29/alpine-linux | - | alpine-linux | queued | pending | Exact-candidate musl OpenRC native/journey/soak obligations | - |
| R29/debian-linux | - | debian-linux | queued | pending | Exact-candidate headless native/journey/soak obligations | - |
| R29/reconciliation | all R29 native subrows | cachyos-linux | queued | pending | Freeze identity, hosted/native/soak/restoration cross-check and final matrix | - |

## Peer requests

No requests have been issued by preparing this dispatcher. Add rows only for a real
bounded need. Ready requests take priority over new work on the addressed hat.
The linked task report holds source/artifacts, exact steps, scope, expected outcome,
fresh run ID and restoration. Each peer writes evidence only in its own journal.

| Request / task | Requesting hat | Peer hat | Mode / report | State | Peer evidence |
|---|---|---|---|---|---|
| `R03/windows-native-reconciliation` | windows | debian-linux | Reconcile completed issue 004 native proof with [R03](reports/R03.md); no peer mutation | completed | [Windows journal](../../../fleet/windows/journal.md); [issue 004](../../../fleet/windows/issues/004-windows-dnsapi-meta-browse-resource-growth.md) |
| `R06/windows-renderer-compile` | cachyos-linux | windows | Exact `d2f6645` native compiler/dependency probe; no installed-host mutation; [procedure](reports/R06-renderer-decision.md#bounded-peer-compile-requests) | completed | [Windows journal](../../../fleet/windows/journal.md#2026-09-05-29--r06-native-windows-renderer-compiler-probe) |
| `R06/alpine-renderer-compile` | cachyos-linux | alpine-linux | Exact `d2f6645` musl compiler/dependency probe; no installed-host mutation; [procedure](reports/R06-renderer-decision.md#bounded-peer-compile-requests) | completed | [Alpine journal](../../../fleet/alpine-linux/journal.md#2026-09-05-1806-utc--r06-native-musl-renderer-compiler-probe) |
| `R06/windows-packaged-renderer` | cachyos-linux | windows | Desktop `c497b3b` native package/live evaluation on own host only; acknowledge before mutation; [procedure](reports/R06-renderer-decision.md#bounded-packaged-peer-requests) | requested | Pending |
| `R06/alpine-packaged-renderer` | cachyos-linux | alpine-linux | Desktop `c497b3b` native musl package/live evaluation on own host only; acknowledge before mutation; [procedure](reports/R06-renderer-decision.md#bounded-packaged-peer-requests) | acknowledged | [Alpine journal](../../../fleet/alpine-linux/journal.md#2026-09-05-1841-utc--r06-packaged-renderer-request-acknowledged) |

States: requested, acknowledged, running, completed, failed, cancelled. A scheduled
mutation requires peer acknowledgement before a candidate/run is armed. Do not
reserve a peer indefinitely; the report names a release condition and expiry,
and missing/expired acknowledgement prevents starting the dependent native run.

## Epic gates

Update only when an entire gate changes state; the epic carries the definition.

| Gate | State | Evidence |
|---|---|---|
| G0 contract/handover | accepted | [R01 report](reports/R01.md); ADR-044/CONTRACT v1; final Windows restoration `b18302b` |
| G1 truth/catalog | queued | - |
| G2 common experience | queued | - |
| G3 install/second machine | queued | - |
| G4 container/local sharing | queued | - |
| G5 diagnosis/trust/recovery | queued | - |
| G6 integrations/developer/docs | queued | - |
| G7 accessibility/candidate | queued | - |
| G8 usability/release review | queued | - |

## Candidate and revalidation

R29 fills the source/lockfile/asset/recipe and platform-artifact manifest once a
candidate is frozen. Record any post-freeze change, affected rows and replacement
freeze here with links to evidence. An unchanged docs-only commit does not relabel
the tested binary. An affected product build cannot reuse stale native evidence.

## Planning-pack validation

The pack itself is checked for local links/source paths, complete IDs, dependency
cycles and mandate/finding coverage. Those checks validate the work orders only.
They do not count as product, fleet or user acceptance.

Validated 2026-09-04: 30 prompts, 32 subrows (53 bounded executions including
unsplit tasks), 212 source entry references and 36 new Markdown files. All source
paths and pack links resolve. Prompt/index/ledger dependencies agree; parent and
subrow graphs are acyclic. Required prompt sections and D01-D10 coverage are present.
The longest prompt is 826 words. Code fences and whitespace checks pass.
Existing documentation-consumer and surface-ledger guards pass; git diff --check
passes. This session created the planning pack only.

Dispatcher validation, 2026-09-04: fleet/task.md now routes Epic 003 to fixed Linux
owners. All 30 task rows and 32 subrows have one owner; the 53 executable slices
cover 14 CachyOS, 18 Debian, 11 Bluefin, 9 Alpine and one reserved Windows row.
Prompt/index/ledger dependencies agree and the expanded graph is acyclic.
460 local link/source references resolve; prompt fences and whitespace pass.
The documentation-consumer and surface-ledger guards pass.

A synthetic routing check (assuming R01 handover and all required source, CI and
Linux/peer checks succeed) permits 50 slices before Windows proof, while leaving
R29/windows, R29/reconciliation and R30 pending. This checks dispatch logic only:
no product tasks, native runs or acceptance gates were executed by preparing
the dispatcher. All task/readiness rows correctly remain queued/pending.
