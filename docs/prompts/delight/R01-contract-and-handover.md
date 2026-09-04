# R01 - Set the product contract and campaign handover

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **A fresh executor can find one current plan and unambiguous owners for catalog, preferences, sharing, diagnostics, and secure setup.**

- Dependencies: None for preparation; activation conditions below still apply.
- Epic gate: G0
- Execution class: design and dispatch handover.
- Status and exact next slice live in [LEDGER.md](LEDGER.md), not this prompt.

## Start here

1. Read [the epic](../../../fleet/epics/003-delight-realignment.md), [CHARTER.md](CHARTER.md),
   [LEDGER.md](LEDGER.md) and [CONTRACT.md](CONTRACT.md).
2. Verify dependency evidence against current code and preserve the worktree.
   Linux execution is authorized through fleet/task.md. Prepare the contract and prove the inherited-run disposition before releasing product dependencies.
3. Read the source set below and nearby tests. Use R01's owner map and R06's component
   map where they exist. New file names in those maps are authoritative.
4. Write the bounded plan in reports/R01.md (or reports/R01-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Starting source

- `.agentic/CONTEXT.md`
- `fleet/coordination.md`
- `fleet/epics/002-observable-domain-boundaries.md`
- `docs/adr/043-observable-domain-boundaries.md`
- `docs/assessment/2026-09-delight-mandates-and-ux-direction.md`
- `docs/assessment/2026-09-sylin-visual-dictionary.md`
- `crates/koi-compose/src/status.rs`
- `crates/koi-compose/src/orchestrator.rs`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. As cachyos-linux, recheck the inherited fleet run and both repository revisions. Record actual facts in CONTRACT.md; do not assume the dated OD-3 schedule completed. The owner has authorized Linux execution through fleet/task.md. Require verified Epic 002 closure, or explicit operator supersession with native restoration, before releasing product dependencies. Contract preparation may proceed while the existing run finishes; this prompt does not cancel it.

2. Write an ADR using the next available number and update CONTRACT.md with exact module/type/route ownership. Use koi-compose for cross-domain projections and explicit coordination, domain facades for resource mutation, koi-serve for transports, and the chosen presentation boundary for user language. Decide where durable service preferences and share intent live; record one owner and startup/shutdown path for each. Avoid a new generic workflow engine or bus.

3. Define Device, Service, Endpoint, Observation, CheckEvidence, and AvailableAction semantics; distinguish discovery, identity, authorization, reachability, and client TLS trust. Specify network scope, source identity, revision reset, correlation precedence, ambiguous identities, durable keys, typed errors, action authorization, and bounded retention. Include example serialized inputs/outputs for a duplicate advertisement, an absent favorite, and a share pending a peer check.

4. Set first-class supported journeys and native matrix from current evidence; decide a minimal HTTP/API sharing path and one secure-service path. Establish client-vs-daemon check location, name-conflict behavior, cancellation/rollback semantics, resource ownership, and migration rules. Record framework choice as pending R06, never choose it here without that spike.

5. Verify the existing Epic 003 branch in fleet/task.md, Linux owner assignments and startup pointers together. When the contract and inherited-run handover are satisfied, record the evidence and Campaign: active in LEDGER.md, update CONTRACT.md and the epic, and accept R01. The execution authority is already recorded; no new routine approval is needed. Otherwise keep R01 implemented/readiness pending with the exact missing evidence. Do not create another dispatcher.

## Acceptance cases

- [ ] Every later task has a named owner and an exact contract or a single explicit decision owned by R06; no undefined 'shared manager' remains.
- [ ] Resolve the conflict with the old June charter in writing: task-oriented commands may change, durable user data must survive, and no repeated plan approval is required.
- [ ] The activation record names the old campaign disposition, current source revisions, restoration evidence where required, and the new dispatcher; authorization alone cannot release implementation dependencies.
- [ ] Source examples cover forbidden remote operator actions, uncertain service identity, old schema handling, process restart, and publication without peer verification.

## Verification

Review the contract against ADR-043, ADR-040, ADR-042 and STACK-0001. Check all named paths and types against the tree; validate the example shapes with the existing serialization tooling once types exist. This task requires no product build or host mutation.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Complete CONTRACT.md and write the ADR; update LEDGER.md with the activation state and exact agreed owner paths. CONTRACT.md must be usable without conversation history.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not select a UI framework, implement the product, terminate a soak or enroll a host as part of contract preparation. Dispatch wiring is already present; reconcile it, do not duplicate it. Settle architecture choices here instead of making later small tasks guess.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
