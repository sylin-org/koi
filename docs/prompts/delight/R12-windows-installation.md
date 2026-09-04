# R12 - Complete the Windows install and lifecycle journey

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **A Windows user installs once and opens a working Koi with automatic background participation.**

- Dependencies: [R11](R11-installation-contract.md), [R09](R09-settings-about-and-surface-consolidation.md)
- Epic gate: G3
- Execution class: Linux source preparation; later Windows native acceptance.
- Status, fixed owner, dependency readiness and exact next slice live in [LEDGER.md](LEDGER.md).
  Its Linux readiness rule qualifies only pending Windows physical proof, never missing source or Linux evidence.

## Start here

1. Read [the epic](../../../fleet/epics/003-delight-realignment.md), [CHARTER.md](CHARTER.md),
   [LEDGER.md](LEDGER.md) and [CONTRACT.md](CONTRACT.md).
2. Verify dependency evidence against current code and preserve the worktree.
   R01 activation is required. A queued plan or missing predecessor contract does not authorize guessing its implementation.
3. Read the source set below and nearby tests. Use R01's owner map and R06's component
   map where they exist. New file names in those maps are authoritative.
4. Write the bounded plan in reports/R12.md (or reports/R12-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Starting source

- `crates/koi/src/platform/windows.rs`
- `crates/koi-serve/src/local_ipc/windows.rs`
- `crates/koi-serve/src/windows_firewall.rs`
- `../koi-desktop/src/main.rs`
- `../koi-desktop/src/service_manager.rs`
- `fleet/briefs/windows.md`
- `docs/adr/040-local-operator-control-plane.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. The assigned bluefin-linux owner completes source/recipe work and Windows-target build checks without mutating a Windows host. Use LEDGER.md's linux-ready rule and record every pending physical case. Native execution is reserved for a later operator-dispatched Windows hat: it records the real service, artifact hashes, SID/DACL, provider, firewall, startup and durable-data baseline, and arms restoration before mutation.

2. Complete R11's recipe for SCM/native prerequisites, durable binary locations, the authenticated named pipe, correct operator identity, desktop reveal and login startup. Reuse native mDNS capability or the actual fallback without duplicate responders.

3. On the later Windows native pass, exercise clean install, rerun, close/reopen, restart, fresh graphical login, in-place upgrade, injected failed-upgrade rollback, uninstall and reinstall. Use real product controls; preserve unrelated host state and identity material according to the removal option. Linux prepares exact procedures and source checks, never fabricated results.

4. The Windows hat checks discovery in both directions with an independent peer, promised hostname resolution and a real endpoint opening, then restores its intended healthy single deployment. Until that evidence lands, this task remains implemented, never accepted.

## Acceptance cases

- [ ] A fresh user completes install then Open without manually starting a daemon or choosing a provider.
- [ ] SYSTEM service and interactive UI connect through correct ACLs; an unrelated ordinary account is refused.
- [ ] Login and restart restore exactly one intended service/workbench; closing UI leaves discovery running.
- [ ] Rollback/uninstall remove only Koi-owned changes and preserve incumbent discovery and unrelated rules.

## Verification

Use locked native Rust/desktop checks and the installed product. Capture source/artifact/PID and peer evidence; a mock installer or generated SCM definition is not native acceptance.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Update the Windows install guide and owned fleet journal, the R12 report and platform matrix. Record any required OS prompt and when it appears.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not weaken the breadcrumb ACL, bypass DAT, silently elevate, kill another user's sessions, or mutate another hat's machine. Plan disruptive login tests with the operator.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
