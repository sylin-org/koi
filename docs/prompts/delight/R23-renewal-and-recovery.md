# R23 - Make renewal and recovery understandable and dependable

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **Users know the real deadline for restoring trust infrastructure and have a tested route back.**

- Dependencies: [R21](R21-secure-service-operation.md), [R22](R22-secure-access-and-client-onboarding.md)
- Epic gate: G5
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
4. Write the bounded plan in reports/R23.md (or reports/R23-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Starting source

- `crates/koi-certmesh/src/core_status_clock.rs`
- `crates/koi-certmesh/src/core_renewal.rs`
- `crates/koi-certmesh/src/core_failover.rs`
- `crates/koi-certmesh/src/backup.rs`
- `crates/koi-certmesh/src/roster.rs`
- `crates/koi-certmesh/src/diagnosis.rs`
- `docs/guides/certmesh-ha-recovery.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Expose last successful renewal, actual earliest affected expiry, active persisted policy and CA availability through authoritative status. Treat backup freshness/restore rehearsal as measured facts; show unknown when no evidence exists.

2. Use service-focused language for urgency and recovery actions. Group repeated renewal failures as one episode; only announce recovery after a successful operation and client check where promised.

3. Execute the supported backup/restore or manual continuity journey with explicit ownership/identity effects. Fix broken guidance or code at the correct owner; keep enrollment and trust-store states coherent after rejoin.

4. Verify certificate reload, daemon/UI restart and bounded outage handling. Provide accurate remaining-validity and ordinary-client revocation explanations; renewal grace never extends a leaf's TLS lifetime.

## Acceptance cases

- [ ] A stored non-default policy gives correct deadlines; the UI does not assume 7/3/1 for every mesh.
- [ ] CA outage produces one actionable episode and the earliest concrete service impact, not an endless healthy/retry loop.
- [ ] A controlled restore/renewal re-establishes the advertised second-client URL and preserves key/identity semantics documented by the runbook.
- [ ] A stale/unverified backup is never described as tested recovery; ordinary leaf validity and Koi-aware revocation are distinguished.

## Verification

Use deterministic time/deadline tests and a real authorized recovery exercise with exact restoration. Do not wait a week or change the host clock to test expiry; use supported test-time fixtures for time-dependent internals.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Update the recovery runbook from the executed operation and expose deadlines/help in secure connection settings.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not build automatic multi-CA failover or enterprise PKI policy as part of this task. Never claim 'instant revocation' for an unexpired ordinary TLS leaf.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
