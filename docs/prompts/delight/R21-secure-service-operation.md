# R21 - Compose names, certificates and routing into secure access

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **Secure setup is one resumable backend operation whose result is an actual service URL.**

- Dependencies: [R11](R11-installation-contract.md), [R19](R19-url-diagnosis.md), [R20](R20-authorized-service-certificates.md)
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
4. Write the bounded plan in reports/R21.md (or reports/R21-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Choose one slice

This task has separately tracked slices: `operation-contract`, `domain-composition`, `recovery-proof`.
Select one applicable dependency-ready slice from LEDGER.md. Execute and report only
that slice; complete the parent task only when all required rows are accepted.
The slice table defines order, owner and narrow deliverable.

## Starting source

- `crates/koi-compose/src/bridges.rs`
- `crates/koi-compose/src/certmesh.rs`
- `crates/koi-compose/src/trust.rs`
- `crates/koi-proxy/src/lib.rs`
- `crates/koi-proxy/src/tls.rs`
- `crates/koi-dns/src/lib.rs`
- `crates/koi-trust/src/repository.rs`
- `docs/adr/043-observable-domain-boundaries.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Use R01's named operation owner and R20's service certificate contract. Compose existing domain commands for name, authorized leaf, listener/proxy and health with an owned intent/resource receipt. Reuse trusted infrastructure and manual entries where valid without claiming their ownership.

2. Track prerequisites and evidence separately: name created, consumer resolution checked, issuer available, leaf installed/reloaded, backend reachable, client trust pending/verified. Domain success is not client success.

3. Implement idempotent resume, partial-failure recovery, window-independent operation ownership and exact cleanup of only resources it created. Reuse R17's proven receipt primitives where appropriate without creating a universal workflow engine.

4. Keep the path useful when resolver adoption or client root import needs a user/OS step. Return the one remaining task, intended URL, public fingerprint and a verification target for R22; never recommend TLS bypass.

## Acceptance cases

- [ ] A valid existing mesh and reachable backend yield a correctly named TLS endpoint through real domain operations.
- [ ] An unavailable CA or occupied name/port returns a specific retained pending/error state; retry continues without duplicate roots/listeners.
- [ ] Cancellation/restart between every resource step leaves recoverable state and preserves the last accepted usable setup.
- [ ] The service is not marked client-verified until the declared client check exists, and stopping owned setup preserves unrelated names/proxies/roots.

## Verification

Run composition failure/cancellation/restart tests, real TLS handshake/SAN validation and cleanup assertions. Include success through existing resources and a conflicting foreign proxy.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Document operation states, resource ownership and resolver/client prerequisites, and update CONTRACT.md for R22 consumption.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not install a CA root as a side effect of browsing, assume Koi DNS is the consumer resolver, or make certmesh into a separate daemon.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
