# R20 - Give a service the right name and authorized certificate

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **The secure-service path can obtain and renew a certificate for its exact authorized URL.**

- Dependencies: [R01](R01-contract-and-handover.md), [R04](R04-service-catalog.md)
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
4. Write the bounded plan in reports/R20.md (or reports/R20-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Starting source

- `crates/koi-certmesh/src/issuance_names.rs`
- `crates/koi-certmesh/src/core_enroll.rs`
- `crates/koi-certmesh/src/core_renewal.rs`
- `crates/koi-certmesh/src/principal.rs`
- `crates/koi-certmesh/src/ca.rs`
- `crates/koi-dns/src/aliases.rs`
- `docs/adr/027-short-lived-leaves-default.md`
- `docs/guides/recipes/container-trusted-cert.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Inspect current host identity/SAN and service certificate facilities; use R01's authorization/ownership contract. Prefer existing issuance/ACME seams when they meet it. Add an explicit service-name grant only where missing.

2. Validate ownership and uniqueness of the intended configured-zone service name; constrain requested SANs to the permitted service/host and preserve immutable crypto labels. Record how name conflicts and renamed/recreated services are handled.

3. Keep keys at the chosen host TLS termination owner. Implement issuance, renewal and live consumer reload input with bounded secret handling and durable state. Do not distribute host private keys into containers.

4. Specify removal/revocation effects for Koi-aware enforcement versus ordinary TLS, including remaining leaf validity. Preserve existing mesh policy and grant/identity storage during migration.

## Acceptance cases

- [ ] The intended service URL is covered by the actual issued leaf; a hostname leaf is not reused for an uncovered alias.
- [ ] An unauthorized requester cannot obtain another service's name or an arbitrary wildcard.
- [ ] Renewal keeps the authorized SANs and reloads the consumer without a broken interval; issuance failure preserves the prior usable material.
- [ ] Logs/status/API never reveal private keys, enrollment secrets or recovery material.

## Verification

Run issuance authorization, SAN, renewal, persistence and negative-caller tests plus the real certmesh exchange where appropriate. R21/R22 own the full client outcome.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Update certificate/name authorization and secret-custody references; record the supported host-termination strategy and explicitly deferred per-workload delivery.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not relax principal checks, broaden all host certificates to every service, or pretend koi.certmesh metadata already injects a workload identity.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
