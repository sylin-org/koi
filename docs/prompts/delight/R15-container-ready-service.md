# R15 - Make an opted-in container become one usable service

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **One announce environment variable or label yields a recognizable service that follows application readiness and lifecycle.**

- Dependencies: [R05](R05-catalog-api-and-preferences.md), [R07](R07-home-launchpad.md), [R11](R11-installation-contract.md)
- Epic gate: G4
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
4. Write the bounded plan in reports/R15.md (or reports/R15-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Starting source

- `crates/koi-runtime/src/instance.rs`
- `crates/koi-runtime/src/docker.rs`
- `crates/koi-runtime/src/heuristics.rs`
- `crates/koi-compose/src/orchestrator.rs`
- `crates/koi-health/src/checker.rs`
- `docs/guides/runtime.md`
- `crates/koi-runtime/tests/docker_integration.rs`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Keep KOI_MDNS_ANNOUNCE and koi.announce shorthand authoritative. Infer a published endpoint only for one unambiguous choice; expose actionable missing-runtime, missing-port, multiple-port and loopback-only cases.

2. Separate runtime-running from app-ready and announcement visibility from reachable evidence. Compose appropriate bounded health/readiness checks through the existing owner; determine HTTP applicability from metadata/protocol evidence, not port alone.

3. Project the opted-in container into the shared catalog once with source details. Follow late port binding, app readiness, rename/recreate, restart, daemon restart and removal, preserving stable preference identity where evidence supports it.

4. Ship a small Compose fixture with delayed HTTP readiness and both label/env shorthand cases. Clarify koi.certmesh request semantics until R20-R22 wire the full secure path; never inject dummy certificates.

## Acceptance cases

- [ ] A started but unready container says Starting and does not claim a working Open; readiness produces a real launch action.
- [ ] An ambiguous/unpublished port yields one concrete setup instruction; unrelated containers remain unadvertised.
- [ ] App stop/recreate/removal updates derived mDNS/DNS/health state without duplicate services or orphaned rules.
- [ ] The service appears and opens on an independent second machine; runtime socket failure preserves honest stale state.

## Verification

Run parser/projection tests plus real Docker and Podman lifecycle fixtures on their claimed native lanes. Retain peer access and withdrawal evidence for R29.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Update runtime guide and the copyable Compose example with exact prerequisites, resulting URL, readiness and cleanup.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not assume every running container is healthy, every known port is HTTP, or a container env var grants access to the host runtime.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
