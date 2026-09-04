# R09 - Consolidate Settings, About, advanced tools and Pond

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **Four top-menu modules reach every supported user task, with advanced access and the full original card preserved.**

- Dependencies: [R08](R08-devices-and-comparison.md)
- Epic gate: G2
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
4. Write the bounded plan in reports/R09.md (or reports/R09-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Starting source

- `../koi-desktop/ui/index.html`
- `../koi-desktop/ui/styles.css`
- `../koi-desktop/ui/app.js`
- `crates/koi-dashboard/src/lib.rs`
- `crates/koi-serve/src/pond.rs`
- `crates/koi-serve/src/pond_ui.rs`
- `docs/adr/042-pond-read-only-lan-adapter.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Inventory every current UI action/route in a coverage table: replacement destination, role, deep link, and removal condition. Include DNS/TXT editing, raw discovery, certificates/audit, health, proxy, UDP, runtime, capability/status and Phone/Pond.

2. Build Settings groups for installation, containers, secure connections, sharing and advanced tools using existing backend operations. Use actual certmesh role states to remove open/member/CA contradictions. Reuse R08 comparison and a bounded diagnostics view.

3. Build About with the original artwork, card anatomy/flavor, actual version and useful links. Preserve native decoration, tray reveal, login startup and close/reopen behavior from the selected R06 shell.

4. Serve the shared view in desktop/local web and a permission-limited Pond projection. Keep operator controls out of Pond at both route and backend boundaries. Retire old duplicate page implementations only after coverage is proven; preserve bookmark migration and valuable advanced deep links.

## Acceptance cases

- [ ] Home/Devices/Settings/About are the only top-level modules; every supported old action is mapped and reachable.
- [ ] The card uses the original 100 px sprite at clean scaling with reduced-motion support; version comes from the build.
- [ ] A member with no local CA sees a coherent member state; reading raw evidence remains easy.
- [ ] A Pond caller cannot execute or discover excluded operator functionality; the displayed shared URL is returned by the real listener, never guessed.

## Verification

Run a route/action coverage review, desktop lifecycle regression checks, and Pond positive/negative adapter tests. Exercise About and advanced pages at 320 px and desktop widths with keyboard focus.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Commit the old-to-new action map and update desktop/web/Pond guides. Remove retired docs only by redirecting/indexing their historical context, not deleting design history.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not turn Settings into an ungrouped dump or remove specialist capabilities merely because they lack a Home tile. Do not ship two permanent competing human frontends.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
