# R26 - Make documentation and contribution paths follow user goals

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **A newcomer or contributor can find the right path without reconstructing project history.**

- Dependencies: [R02](R02-critical-documentation-truth.md), [R09](R09-settings-about-and-surface-consolidation.md), [R14](R14-automatic-second-machine.md), [R15](R15-container-ready-service.md), [R18](R18-share-service-experience.md), [R22](R22-secure-access-and-client-onboarding.md), [R23](R23-renewal-and-recovery.md), [R24](R24-finished-acme-integration.md), [R25](R25-developer-and-agent-experience.md)
- Epic gate: G6
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
4. Write the bounded plan in reports/R26.md (or reports/R26-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Starting source

- `README.md`
- `CONTRIBUTING.md`
- `docs/reference/cli.md`
- `docs/MEMORY.md`
- `.agentic/CONTEXT.md`
- `docs/prompts/README.md`
- `docs/SURFACES.md`
- `docs/tutorials/getting-started.md`
- `docs/guides/troubleshooting.md`
- `docs/reference/architecture.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Reorganize the entry layer around install/use a service, add another machine, containers, share a local app, secure access, troubleshoot, automate and contribute. Distinguish published behavior, development changes, compatibility/support and historical evidence.

2. Execute every critical command/configuration/URL in the release tutorials against the actual candidate fixtures. Consolidate policy/auth/version facts by linking to their authoritative contract instead of repeating handwritten copies.

3. Update contributor startup to the current epic, charter and checks; remove outdated redirected-stdin/default-mode examples and stale ownership references. Preserve ADRs and assessment history as dated evidence.

4. Prepare a short truthful limits page covering network scope, root/client trust, revocation, manual continuity, workload-key delivery and platform preview status. Link advanced discovery/DNS/UDP/MCP/ACME/embedding recipes without making beginners read them.

## Acceptance cases

- [ ] Each persona reaches one relevant tested journey from the README in at most two navigation choices.
- [ ] Every advertised command/example targets the intended released/development version and performs the stated result.
- [ ] A new executor finds one active dispatcher and knows the old P01-P14 stash is historical; no stale 'current' links compete.
- [ ] Supported-platform/client claims point to exact evidence; broken links, unexplained library errors and placeholder output are absent.

## Verification

Run existing documentation/surface/leak/link checks plus executable tutorial fixtures; manually follow install, secure URL and contributor paths from a clean starting point. Do not run a Rust rebuild for prose alone.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

This is the documentation convergence task; record an inventory of critical pages, executed examples and any remaining version-scoped limits.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not delete historical decisions, add a second status ledger, or claim planned features ship because their prompts exist.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
