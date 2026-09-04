# R08 - Make Devices answer where services run

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **Devices groups hosted services and provides a truthful comparison when discovery differs.**

- Dependencies: [R07](R07-home-launchpad.md)
- Epic gate: G2
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
4. Write the bounded plan in reports/R08.md (or reports/R08-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Starting source

- `../koi-desktop/ui/app.js`
- `../koi-desktop/src/local_daemon.rs`
- `crates/koi-compose/src/status.rs`
- `crates/koi-serve/src/inventory.rs`
- `docs/adr/040-local-operator-control-plane.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Build device rows/details from the shared catalog, distinguishing this device, discovered peers, joined identity and unavailable peers. Show service count only for the declared filter/scope.

2. Navigate from a device to its services without creating a second service inventory. Preserve friendly device labels and ambiguity when host correlation is uncertain.

3. Move Diff into 'Compare what devices can see' on device details and diagnostics. Resolve eligible peers automatically; use the authorized peer read path and state its access requirement.

4. Render not configured, not run, comparing, no differences, differences and failed/incomplete comparison as distinct states. Attach observer/time/network scope so a missing peer never looks like a successful comparison.

## Acceptance cases

- [ ] Two devices hosting same-named apps remain distinguishable and navigate to the correct endpoints.
- [ ] A machine found through mDNS is not labeled enrolled or trusted.
- [ ] Opening comparison without a second peer says to choose/connect one, not 'all quiet'.
- [ ] Unavailable/unauthorized peer produces an incomplete result with a useful action; two successful snapshots can produce a true no-differences result.

## Verification

Run catalog/device interaction tests and controlled comparison tests for success, timeout, auth refusal and incomparable scopes. Retain a physical two-peer demonstration for R29.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Update device and comparison help, including discovery versus joining and the comparison prerequisites.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not ask for an IP address when an eligible discovered peer exists or infer successful comparison from an empty result array.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
