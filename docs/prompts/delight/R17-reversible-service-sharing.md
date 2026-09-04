# R17 - Own publication, routing and firewall changes as one share

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **An explicit share makes one chosen local HTTP/API service reachable and Stop sharing reverses Koi's owned work.**

- Dependencies: [R05](R05-catalog-api-and-preferences.md), [R11](R11-installation-contract.md), [R16](R16-local-service-detection.md)
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
4. Write the bounded plan in reports/R17.md (or reports/R17-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Choose one slice

This task has separately tracked slices: `intent-contract`, `routing-and-names`, `windows-firewall`, `linux-firewall`, `recovery-proof`.
Select one applicable dependency-ready slice from LEDGER.md. Execute and report only
that slice; complete the parent task only when all required rows are accepted.
The slice table defines order, owner and narrow deliverable.

## Starting source

- `crates/koi-compose/src/orchestrator.rs`
- `crates/koi-mdns/src/lib.rs`
- `crates/koi-dns/src/aliases.rs`
- `crates/koi-proxy/src/listener.rs`
- `crates/koi-proxy/src/safety.rs`
- `crates/koi-serve/src/windows_firewall.rs`
- `crates/koi/src/platform/recipes/transaction.rs`
- `docs/adr/043-observable-domain-boundaries.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Follow the share owner/ports selected by R01. Persist a typed share intent and resource receipt before mutation. Scope the minimum release path to local HTTP/API forwarding over an explicitly selected private network; support existing direct reachability without claiming to own foreign access.

2. Implement name availability/conflict handling and actual hostname resolution, not just PTR advertisement. For loopback services, use a Koi-owned bounded forwarder preserving the application's binding. Support IPv4/IPv6 or return a precise unsupported mode; do not silently drop address scope.

3. Coordinate exact scoped firewall access, listener, name and advertisement with durable retry/rollback. Fence by owner/generation, preserve manual/foreign resources, define start/stop/idempotency/cancellation/crash recovery and deny public-network sharing by default.

4. Publish honest progress and terminal evidence: locally shared, peer verification pending/succeeded, partial failure, stopped. A peer check is a separate observed fact. Stop removes only Koi-owned publication/routing/rules and leaves the original app running.

## Acceptance cases

- [ ] A loopback fixture becomes resolvable and callable from an independent peer through the resulting address; a name/port conflict is handled before false success.
- [ ] Cancellation or process loss after each admitted step is recoverable; repeated Share/Stop does not leak resources.
- [ ] Stop removes Koi's remote path while local access still succeeds. If another path pre-existed, UI accurately says it may remain accessible.
- [ ] The serving path enforces the selected network scope; neither discovery nor certmesh membership is misrepresented as access control.

## Verification

Use transaction fault injection at every external-effect boundary, forwarding/bind/input bounds, wrong-network/refused calls and native firewall ownership tests. Execute physical verification only through the assigned hats; Windows and Linux records are required by R29.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Document the sharing state/resource contract, conflict behavior, access scope, failure recovery and rollback. Provide exact daemon/API handoff for R18.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not automatically modify the application's config, expose database/admin listeners, grant all-interface access, delete foreign firewall rules, or add protected-members-only wording without an actual enforcement path.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
