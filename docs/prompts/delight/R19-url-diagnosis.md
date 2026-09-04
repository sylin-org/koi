# R19 - Explain why a specific service URL fails

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **A user selects a failed service and receives a precise, evidenced next action.**

- Dependencies: [R04](R04-service-catalog.md), [R07](R07-home-launchpad.md)
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
4. Write the bounded plan in reports/R19.md (or reports/R19-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Starting source

- `crates/koi-certmesh/src/diagnosis.rs`
- `crates/koi-trust/src/lib.rs`
- `crates/koi-dns/src/resolver.rs`
- `crates/koi-health/src/checker.rs`
- `crates/koi-proxy/src/safety.rs`
- `crates/koi/src/commands`
- `docs/guides/troubleshooting.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Implement CONTRACT.md's bounded diagnosis owner taking a service ID or explicit HTTP(S) URL. Validate inputs, scope and caller authority; use existing domain status and guarded probes.

2. Separate name resolution on Koi/OS/client, target connection, firewall evidence where actually known, TLS SAN/root/expiry, proxy listener and backend health. Report unknown or not tested when a layer is unobservable; a timeout alone does not prove a firewall block.

3. Return a structured report with observer/client, timestamp, target, outcomes and at most two contextual recovery actions. Add CLI/HTTP/local UI surfaces that render the same report without inventing success.

4. Make mutating remedies explicit commands with scope, owner and retry semantics. Read-only diagnosis must not install roots, change resolvers, open firewall rules or disable validation.

## Acceptance cases

- [ ] Wrong name, unreachable host, SAN mismatch, missing root, expired leaf and unhealthy backend have distinct supported evidence or honest unknown status.
- [ ] Diagnosing from the daemon never asserts a phone/browser trusts the issuer.
- [ ] URL/userinfo/secrets, redirects, probe size/time/concurrency and remote caller boundaries are handled without leaking credentials or exposing a generic network proxy.
- [ ] The suggested action fixes the target fixture; the rerun reports recovery only after checking the result.

## Verification

Use controlled resolver/TLS/backend fixtures and command/report parity tests, including redirects and IPv6. Perform one physical failing-then-fixed client journey without -k or certificate bypass.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Document diagnosis fields, safe next actions and limitations; update troubleshooting around user symptoms and URLs.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not build another full scanner, a generic shell-command repair facility, or label all TLS problems 'untrusted device'.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
