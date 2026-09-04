# R28 - Make routine CI validate the actual development and candidate tree

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **Green status identifies the exact tree and checks the contracts users depend on.**

- Dependencies: [R01](R01-contract-and-handover.md)
- Epic gate: G7
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
4. Write the bounded plan in reports/R28.md (or reports/R28-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Starting source

- `.github/workflows/ci.yml`
- `.github/workflows/qa.yml`
- `.github/workflows/release.yml`
- `.github/workflows/publish.yml`
- `scripts/release-version.test.mjs`
- `scripts/release-manifest.test.mjs`
- `scripts/check-lean-embedded.sh`
- `scripts/check-publish-list.sh`
- `packages/ts/test/client.test.js`
- `packages/python/tests/test_client.py`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Inspect current failures/triggers before changing anything. Add appropriate dev/PR and explicit candidate validation coverage; record exact checked commit. Preserve least-privilege workflow permissions and separate validation from publishing.

2. Include release/channel/manifest/launcher, TS/Python client and selected frontend checks in ordinary CI as they exist; later tasks extend the same pipeline. Keep locked Rust tests, strict Clippy, formatting, MSRV, architecture, lean closure and supply-chain checks.

3. Make ephemeral ports/test isolation appropriate in repository tests; distinguish required platform dependencies from accidental heavy closure. Fix actual failures rather than blanket-skipping native tests or weakening guards.

4. Produce one candidate validation summary joining source SHA(s), artifact manifest and links to hosted/native evidence. Early completion proves CI infrastructure only; R29 must obtain a fresh complete run after all shipping changes land.

## Acceptance cases

- [ ] A dev change gets the intended hosted checks on its exact SHA; old main failure is neither hidden nor treated as proof of new code.
- [ ] Client/version/bootstrap checks fail on a deliberately incompatible fixture and pass on corrected contracts.
- [ ] No validation job can publish packages or mutate the fleet by accident.
- [ ] Missing/skipped/failing required jobs prevent candidate acceptance; allowed preview targets are explicitly qualified.

## Verification

Validate workflow syntax and execute changed scripts/tests locally. Obtain hosted evidence only when an authorized push/dispatch is available; otherwise mark implementation-only and leave hosted acceptance pending. R29 requires actual run URLs and checked SHAs.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Update contributor check commands and release validation reference. Record assessment D05 disposition and the exact candidate-report format.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not dispatch a release, sign/tag/upload packages, fake CI run URLs or weaken the dependency/security guards to get green.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
