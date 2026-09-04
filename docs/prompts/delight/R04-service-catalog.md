# R04 - Build the authoritative service catalog projection

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **Every presentation reads the same coherent devices, services, endpoints, conditions, and actions.**

- Dependencies: [R01](R01-contract-and-handover.md), [R03](R03-discovery-record-correctness.md)
- Epic gate: G1
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
4. Write the bounded plan in reports/R04.md (or reports/R04-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Starting source

- `crates/koi-compose/src/status.rs`
- `crates/koi-compose/src/snapshot.rs`
- `crates/koi-compose/src/cores.rs`
- `crates/koi-common/src/integration.rs`
- `crates/koi-serve/src/inventory.rs`
- `crates/koi-dashboard/src/forward.rs`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Use CONTRACT.md's chosen types/placement; map current specialized domain snapshots to that model. If a named source moved, locate it with rg and update the handoff before editing.

2. Implement evidence-based correlation and stable IDs with network scope. Merge multiple advertisements only when identity/endpoint evidence justifies it; retain provenance and ambiguity. One device may host several unrelated services.

3. Separate observed/starting/responding/absent conditions from device membership, transport encryption and client trust. Each positive check carries observer, time, target and expiry/freshness; allowed actions derive from protocol and caller capability.

4. Subscribe through authoritative watch feeds; handle startup, coalescing, lag, source closure and process restart without rebuilding truth from lossy events. Bound transient memory and join the owner at shutdown.

## Acceptance cases

- [ ] HTTP plus a companion advertisement for the same proven app yields one service with two sources; similar names on different devices remain separate.
- [ ] Source observation loss retains last known data with stale state, while explicit withdrawal updates availability.
- [ ] Reordering, duplicate events and process-local revision resets cannot resurrect removed entries or merge networks.
- [ ] An API-only endpoint offers connection details; an unknown TCP listener never gets an invented web Open action.

## Verification

Use deterministic projection fixtures including conflicting names, IPv6/interface-scoped endpoints, churn, lost watchers, and time-based freshness. Run koi-compose and architecture tests under CHARTER.md; no domain private storage reads.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Document the stable catalog contract, correlation examples, retention limits and consumer update rules; record exact new source paths in CONTRACT.md.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not create a second domain state machine in the frontend, a global registry, or a generic event bus. Do not use a single 'Trusted' boolean.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
