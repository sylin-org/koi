# R02 - Correct high-consequence claims and pin their contracts

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **Users get correct certificate, recovery, authentication, revocation, and installation advice for the version they actually use.**

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
4. Write the bounded plan in reports/R02.md (or reports/R02-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Starting source

- `docs/assessment/2026-09-delight-and-1.0-assessment.md`
- `docs/guides/certmesh-ha-recovery.md`
- `docs/tutorials/trusted-https.md`
- `SECURITY.md`
- `docs/reference/security-model.md`
- `crates/koi-certmesh/src/roster.rs`
- `crates/koi-certmesh/src/issuance_names.rs`
- `crates/koi-serve/src/http.rs`
- `install.sh`
- `install.ps1`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Reproduce or retire assessment findings D01, D02, D03, D06, D09, and D10 against current source. Record changed findings with file/line and test evidence; do not assume old observations still reproduce.

2. Correct recovery guidance for persisted policy versus new-mesh defaults, actual certificate validity, renewal grace, and earliest expiry. Correct SAN/default-zone and service-alias statements without promising every client uses the OS root store.

3. Create one authoritative tested route/auth matrix covering local operator, authenticated remote principal, public bootstrap/enrollment, and Pond reads. Link SECURITY.md and guides to it; assert actual mounted route behavior rather than matching prose strings.

4. Make bootstrap next-action output valid for the chosen artifact's mode contract, and distinguish download-only from service installation where still applicable. Correct certmesh metadata and ACME/revocation claims now; future automatic features must be labeled planned until their task proves them.

## Acceptance cases

- [ ] New meshes and an existing mesh with different stored policy produce correct recovery guidance; grace is never described as extending TLS validity.
- [ ] Public bootstrap succeeds and remote full status/operator mutations fail or require the actual supported authority; test the intentional enrollment exception.
- [ ] Run the installer's printed next action for each claimed version/channel fixture without relying on an already installed daemon.
- [ ] The README no longer implies a flag injects workload certificates; revocation advice distinguishes Koi-aware and ordinary TLS clients.

## Verification

Run focused policy/name and route authorization tests plus scripts/release-version.test.mjs and scripts/release-manifest.test.mjs when installer/channel output changes. Check modified shell/PowerShell syntax and execute representative snippets in authorized fixtures. Apply the Rust gates in CHARTER.md if code changes.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Update affected guides/tutorials, SECURITY.md, security-model.md, bootstrap output, and the finding disposition table in CONTRACT.md.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not weaken security or change certificate policy just to make old documentation true. Do not relabel old hosted failures as current runtime defects.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
