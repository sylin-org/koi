# R03 - Fix discovery classification at its source

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **The catalog receives real service types and instances without hostname/type pollution.**

- Dependencies: [R01](R01-contract-and-handover.md)
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
4. Write the bounded plan in reports/R03.md (or reports/R03-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Starting source

- `crates/koi-mdns/src/windows_dnsapi.rs`
- `crates/koi-mdns/src/discovery.rs`
- `crates/koi-mdns/src/lib.rs`
- `docs/adr/037-mdns-provider-selection.md`
- `docs/adr/039-mdns-control-plane-ownership.md`
- `docs/assessment/2026-09-assessment-verification.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Build a minimized mixed PTR/SRV/TXT/A/AAAA fixture from the reported failure shape, with synthetic names. Trace the query owner and callback through the provider and discovery projection; determine the defect boundary before editing.

2. Validate DNS-SD semantics, including service enumeration, normal browse, subtypes, escaped instance labels, and case/trailing-dot normalization. Use primary protocol documentation if uncertain. Preserve unknown but valid services.

3. Correct the responsible provider/shared boundary, keeping provider-specific parsing behind its adapter and normalization in its existing owner. Prevent callbacks from publishing into a retired generation.

4. Verify withdrawal, duplicate answers, provider fallback and snapshot/event ordering. Leave source provenance available for diagnostics.

## Acceptance cases

- [ ] Hostnames and full instance names never enter the service-type collection from the fixture.
- [ ] Valid subtype discovery and unknown service types remain visible; no simplistic underscore regex silently discards legitimate records.
- [ ] Duplicate/mixed answers converge; goodbye, expiry and provider loss do not leave ghost catalog entries.
- [ ] A physical Windows observation is recorded when available; repository regression evidence is kept separate from native acceptance.

## Verification

Run focused koi-mdns regression tests and architecture gates. Use the native provider-transition recipe only through an authorized fleet assignment; R29 will repeat the necessary evidence on the final candidate.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Update the D04 disposition and the relevant mDNS reference/diagnostic notes with root cause and reproducible fixture.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not hide bad types only in CSS or UI filters. Do not sanitize by removing all unfamiliar types or treat a port heuristic as proof of an HTTP app.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
