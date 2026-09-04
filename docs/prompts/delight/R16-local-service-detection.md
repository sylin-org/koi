# R16 - Detect useful services already running on this machine

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **Koi can suggest a local Ollama or other identified service without publishing it.**

- Dependencies: [R04](R04-service-catalog.md), [R11](R11-installation-contract.md)
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
4. Write the bounded plan in reports/R16.md (or reports/R16-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Choose one slice

This task has separately tracked slices: `contract`, `windows`, `linux`.
Select one applicable dependency-ready slice from LEDGER.md. Execute and report only
that slice; complete the parent task only when all required rows are accepted.
The slice table defines order, owner and narrow deliverable.

## Starting source

- `crates/koi-runtime/src/backend.rs`
- `crates/koi-runtime/src/docker.rs`
- `crates/koi-runtime/src/instance.rs`
- `crates/koi-common/src/integration.rs`
- `crates/koi/src/platform/mod.rs`
- `docs/assessment/2026-09-delight-mandates-and-ux-direction.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Execute one ledger subrow at a time: first contract/common projection, then Windows adapter or Linux adapter. Follow R01's selected owner. Define a candidate with evidence, local endpoint, process/runtime provenance where available, confidence, already-managed status and supported share mode.

2. Use OS listener information and accessible runtime metadata with bounded read-only identification probes. Start with Ollama plus one generic manually named HTTP candidate. Do not read process environment secrets or require broad privileged scans.

3. Treat a familiar port as a hint. Confirm a recognizable endpoint/response before naming Ollama; unknowns remain unknown. Rate-limit/cancel scanning, handle IPv4/IPv6, denied process metadata and network changes.

4. Integrate deduplication with existing runtime and network catalog so already-published or dismissed candidates do not repeatedly prompt. Publish candidates as local-only state; mutation is exclusively a later explicit Share action.

## Acceptance cases

- [ ] A known loopback-only Ollama fixture is detected and identified; a different service on 11434 is not mislabeled.
- [ ] Unknown listeners and permission-denied metadata yield useful qualified state without failing discovery.
- [ ] Already managed containers are not suggested twice, and dismiss persists via R05.
- [ ] Detection opens no firewall/listener, publishes no name and imports no trust; scan resource use remains bounded.

## Verification

Run adapter fixture tests and native listener identification on Windows and Linux. Use official Ollama documentation for current probe semantics; no request may trigger model download/generation. All three subrows are required for task acceptance.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Document candidate evidence and supported recognizers, privacy/resource bounds and manual naming; update CONTRACT.md adapter paths.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not create a network-wide port scanner, a plugin registry, a catalog of guessed apps, or an elevation prompt on every launch.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
