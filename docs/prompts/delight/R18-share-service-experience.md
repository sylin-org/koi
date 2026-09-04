# R18 - Deliver the local discovery to Share experience

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **Home offers 'Ollama is running on this computer' and one deliberate Share completes the supported work.**

- Dependencies: [R07](R07-home-launchpad.md), [R16](R16-local-service-detection.md), [R17](R17-reversible-service-sharing.md)
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
4. Write the bounded plan in reports/R18.md (or reports/R18-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Starting source

- `docs/assessment/2026-09-delight-mandates-and-ux-direction.md`
- `docs/assessment/2026-09-sylin-visual-dictionary.md`
- `../koi-desktop/src/local_daemon.rs`
- `crates/koi-serve/src/http.rs`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Use R06's component map and R16/R17's real contracts. Present a dismissible local-only service strip with detected identity and a Share entry. Keep ordinary network services primary once suggestions are dismissed.

2. Pre-fill the verified candidate name/endpoint and smallest supported network scope. Show who can call it, sign-in requirement and HTTP/HTTPS truth before the final Share action; use plain wording and technical change details on demand.

3. Wire progress and failure/retry to the backend operation so closing/reopening the window resumes the same share. Do not add a second confirmation after the user has reviewed and chosen Share, apart from required OS authorization.

4. Show the resulting real address and appropriate Open/copy/connect action. For Ollama, show an API base URL rather than pretend it has a browser UI. Provide Stop sharing and accurately distinguish retained local/foreign access.

## Acceptance cases

- [ ] The user can accept sane defaults and share with one committing action after the review; no manual firewall command is needed on supported environments.
- [ ] A failed alias/listener/firewall step is explained specifically and never appears as success.
- [ ] Closing UI during sharing then reopening shows the retained operation and eventual true result.
- [ ] Stop removes the service's Koi share from remote catalog/access while the local app remains running; dismiss prevents repetitive suggestions.

## Verification

Exercise the full UI against real sharing on authorized Windows and Linux fixtures, including a loopback-only API, partial failure and reopen. Test keyboard, copy/address safety and access-scope wording.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Write a concise local sharing guide using the actual flow and a screenshot from the real UI, plus one Ollama client connection example verified against current official docs.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not turn an illustrative mockup's sample data into production behavior or imply public internet, all subnets, or joined-only access.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
