# R05 - Expose the catalog and durable personal preferences

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **Clients can read and follow the catalog, while favorites, aliases and dismissed suggestions survive restart.**

- Dependencies: [R04](R04-service-catalog.md)
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
4. Write the bounded plan in reports/R05.md (or reports/R05-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Starting source

- `crates/koi-serve/src/http.rs`
- `crates/koi-serve/src/local_ipc/mod.rs`
- `crates/koi-serve/src/inventory.rs`
- `crates/koi-client/src/lib.rs`
- `crates/koi-config/src/lib.rs`
- `../koi-desktop/ui/app.js`
- `../koi-desktop/src/local_daemon.rs`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Add the typed catalog snapshot/subscription and preference commands at CONTRACT.md's transport seams. Preserve authenticated local control and use capability-appropriate remote projections.

2. Persist user intent in its named owner with atomic/versioned updates and deterministic conflict handling. Migrate existing watched/favorite data with a backup and rollback path; do not copy a whole raw discovery cache into durable preferences.

3. Support favorites, friendly aliases and dismissing a local suggestion without changing the real network service name. Preserve an absent favorite with its last known context and honest freshness.

4. Version the contract and handle mixed desktop/daemon versions with a clear compatibility error. Keep shared service identity separate from per-user preferences and from what Pond may disclose.

## Acceptance cases

- [ ] Favoriting, renaming locally, dismissing and restarting preserve intent; rediscovery reconnects to the right stable service.
- [ ] An absent favorite is visible and marked absent; a same-named stranger does not inherit it.
- [ ] A lost subscription refetches a snapshot; wrong-account and remote unauthorized preference mutations are rejected.
- [ ] A migration failure retains original preferences and exposes one recoverable error; secrets and operator data never appear in Pond.

## Verification

Run persistence interruption and transport authorization tests, schema round-trips and client adapter tests. Test existing stored preference fixtures and a mismatched desktop/daemon pair.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Update HTTP/local IPC reference and preference migration contract; publish sample catalog responses for R07-R10.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not use browser localStorage as the only durable product preference store or promote private preferences to network-wide authority.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
