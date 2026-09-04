# R29 - Validate one exact realignment candidate across the native fleet

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **The release promise is backed by exact installed artifacts, native lifecycle evidence and full journey results.**

- Dependencies: [R02](R02-critical-documentation-truth.md), [R03](R03-discovery-record-correctness.md), [R09](R09-settings-about-and-surface-consolidation.md), [R10](R10-meaningful-activity.md), [R12](R12-windows-installation.md), [R13](R13-linux-installation.md), [R14](R14-automatic-second-machine.md), [R15](R15-container-ready-service.md), [R18](R18-share-service-experience.md), [R23](R23-renewal-and-recovery.md), [R24](R24-finished-acme-integration.md), [R25](R25-developer-and-agent-experience.md), [R26](R26-documentation-and-contributor-path.md), [R27](R27-accessibility-and-interaction-proof.md), [R28](R28-ci-and-release-contracts.md)
- Epic gate: G7
- Execution class: native acceptance through the activated fleet protocol.
- Status, fixed owner, dependency readiness and exact next slice live in [LEDGER.md](LEDGER.md).
  Its Linux readiness rule qualifies only pending Windows physical proof, never missing source or Linux evidence.

## Start here

1. Read [the epic](../../../fleet/epics/003-delight-realignment.md), [CHARTER.md](CHARTER.md),
   [LEDGER.md](LEDGER.md) and [CONTRACT.md](CONTRACT.md).
2. Verify dependency evidence against current code and preserve the worktree.
   R01 activation is required. A queued plan or missing predecessor contract does not authorize guessing its implementation.
3. Read the source set below and nearby tests. Use R01's owner map and R06's component
   map where they exist. New file names in those maps are authoritative.
4. Write the bounded plan in reports/R29.md (or reports/R29-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Choose one slice

This task has separately tracked slices: `windows`, `cachyos-linux`, `bluefin-linux`, `alpine-linux`, `debian-linux`, `reconciliation`.
Select one applicable dependency-ready slice from LEDGER.md. Execute and report only
that slice; complete the parent task only when all required rows are accepted.
The slice table defines order, owner and narrow deliverable.

## Starting source

- `fleet/PROTOCOL.md`
- `fleet/coordination.md`
- `fleet/task.md`
- `docs/SURFACES.md`
- `fleet/epics/001-productization-hardening.md`
- `fleet/epics/002-observable-domain-boundaries.md`
- `docs/testing/mdns-provider-transition.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. CachyOS freezes the source manifest before native rows start. Full acceptance requires accepted predecessors; the ledger permits a clearly labeled Linux development candidate when only listed Windows physical cases remain. All required Linux and hosted checks still pass first. Record both repo SHAs or unified source, lockfiles, assets/recipes, artifact hashes, versions and CI runs. Reconcile earlier Windows cases before the Windows/final pass; never relabel an old binary.

2. Run only the current host's subrow through fleet/task.md. Coordinate peer reads and system changes under the existing ownership protocol. Use one installed Koi, actual control surfaces and declared native supervisors; no isolated daemon, fake provider or checkout UI counts as physical acceptance.

3. Exercise the epic's G3-G7 matrix: install/upgrade/rollback/remove/reinstall; automatic second-machine discovery; container readiness; local-share/stop; correct second-client HTTPS plus renewal/recovery; UI/CLI/Pond authority boundaries; restart/session/network/provider churn and resource cleanup.

4. Complete the applicable existing soak requirements on the new candidate: at least six hours for development evidence and 24 hours for release-quality evidence, with bounded resources, deliberate faults and exact restoration. Reuse collectors and consolidate existing valid evidence rather than rerunning unrelated green physical gates without cause.

5. Reconcile every required row with both sides' evidence, final state and hosted checks. Product/dependency/installer/shipped-asset changes invalidate affected results and require a named refreeze/retest; documentation-only changes preserve product evidence while examples/claims are rechecked.

## Acceptance cases

- [ ] Every claimed native platform and libc has its required physical row or is clearly preview/unverified; macOS cannot inherit Linux evidence.
- [ ] All core promises use the exact candidate artifacts and real clients without TLS bypass, manual undocumented setup, extra daemons or widened operator exposure.
- [ ] Soak and native cleanup are verified, not merely attempted; every host has its intended healthy process/resource state.
- [ ] The consolidated verdict fails if a required job/journey/restoration is missing, even when most tests pass.

## Verification

Run full locked workspace/native gates, desktop/selected UI tests, client/version/security/architecture checks and actual cross-host journeys. Record same-candidate evidence and expected-negative exit status plus content. Reconciliation is a separate ledger subrow.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Update only owned hat journals, docs/SURFACES.md when claims change, reports and the candidate acceptance summary. Keep historical evidence intact.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not launch other hats, send them tool messages, or perform their host mutations without explicit coordination authority. Do not reuse dated run IDs/times from Epic 002.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
