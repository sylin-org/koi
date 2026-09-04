# R11 - Make installation a durable path to a working Koi

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **One recommended install path selects compatible components and finishes with a usable service entry point.**

- Dependencies: [R01](R01-contract-and-handover.md), [R06](R06-rust-ui-and-family-foundation.md)
- Epic gate: G3
- Execution class: repository implementation; any native evidence uses the fleet protocol.
- Status, fixed owner, dependency readiness and exact next slice live in [LEDGER.md](LEDGER.md).
  Its Linux readiness rule qualifies only pending Windows physical proof, never missing source or Linux evidence.

## Start here

1. Read [the epic](../../../fleet/epics/003-delight-realignment.md), [CHARTER.md](CHARTER.md),
   [LEDGER.md](LEDGER.md) and [CONTRACT.md](CONTRACT.md).
2. Verify dependency evidence against current code and preserve the worktree.
   R01 activation is required. A queued plan or missing predecessor contract does not authorize guessing its implementation.
3. Read the source set below and nearby tests. Use R01's owner map and R06's component
   map where they exist. New file names in those maps are authoritative.
4. Write the bounded plan in reports/R11.md (or reports/R11-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Choose one slice

This task has separately tracked slices: `result-contract`, `restart-and-rollback`.
Select one applicable dependency-ready slice from LEDGER.md. Execute and report only
that slice; complete the parent task only when all required rows are accepted.
The slice table defines order, owner and narrow deliverable.

## Starting source

- `install.sh`
- `install.ps1`
- `crates/koi/src/platform/mod.rs`
- `crates/koi/src/platform/install_lock.rs`
- `crates/koi/src/platform/recipes/transaction.rs`
- `docs/adr/025-release-channels-and-bootstrap-contract.md`
- `docs/adr/036-recipe-installer.md`
- `../koi-desktop/src/service_manager.rs`
- `packaging/README.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Specify and implement the common installation result/transaction contract: selected channel/version and compatible desktop pair, durable paths, background service readiness, provider capabilities, startup, local control, final URL or workbench entry, and actionable failure.

2. Make the recommended desktop flow arrange daemon plus workbench and one coherent upgrade path; headless install ends with the running daemon and useful command/URL. Keep explicitly chosen portable/download-only modes distinguishable.

3. Reuse existing transaction/lock/receipt machinery. Persist intent before host changes; recover after interruption, failed health checks, incompatible versions and concurrent installs. Preserve settings, favorites, identities and existing native providers.

4. Select sane defaults from measured platform capability. Reuse discovery support where sufficient and fill missing browse/publication capability with a supported fallback. No automatic trust enrollment, root import or arbitrary service exposure on install.

## Acceptance cases

- [ ] Success cannot be returned before the product's service/local-control readiness checks pass.
- [ ] An interrupted or failed upgrade leaves either the old healthy product or an explicit resumable failure with its owned state tracked.
- [ ] Fresh install chooses versions deterministically; rerun is idempotent and no second daemon/workbench is created.
- [ ] The next action emitted by every mode is executable and matches the selected artifact rather than checkout-only behavior.

## Verification

Run transaction failure-injection and version/manifest tests, platform recipe unit tests, and native gates on the available host. R12/R13 own actual platform installation acceptance.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Update install/upgrade contract and packaging compatibility manifest, including artifact pairing and user-data preservation.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not call downloading an executable a completed installation or start an alternate-port daemon to make health checks pass.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
