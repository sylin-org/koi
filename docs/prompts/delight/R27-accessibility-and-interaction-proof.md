# R27 - Prove the real UI is usable with keyboard, touch and interruption

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **The preserved Sylin style supports clear actions, readable text and accessible complete journeys.**

- Dependencies: [R09](R09-settings-about-and-surface-consolidation.md), [R10](R10-meaningful-activity.md), [R18](R18-share-service-experience.md), [R22](R22-secure-access-and-client-onboarding.md)
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
4. Write the bounded plan in reports/R27.md (or reports/R27-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Starting source

- `docs/assessment/2026-09-sylin-visual-dictionary.md`
- `../koi-desktop/ui/app.test.mjs`
- `crates/koi-dashboard/tests/xss.rs`
- `docs/adr/033-koi-desktop-workbench.md`
- `docs/adr/042-pond-read-only-lan-adapter.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Test the real selected frontend, not the earlier HTML study or DOM stub alone. Cover Home search/Open/details, Devices comparison, Settings advanced tools, sharing review/progress/stop, secure setup and About.

2. Use semantic controls, accessible names/state, visible focus, logical order, keyboard dismissal/return, screen-reader announcements and safe external links. Test zoom, long names, empty/loading/error states and focus during reactive reordering.

3. Measure text/action/status contrast and target affordances. Preserve the family palette while using a stronger ink token or larger type where a critical label fails; 9 px metadata styling is not a mandate to make functional copy unreadable.

4. Verify 320/390 px, normal desktop and 200% zoom, reduced motion, touch, dark native chrome and offline asset loading. Cover daemon reconnect/UI close and restoration without losing user work. Capture only scrubbed fixture data.

## Acceptance cases

- [ ] A keyboard-only user can complete find/open/share/details without a click-only span/div or focus trap.
- [ ] Important text and actions meet the documented accessibility target with measured values; state is not encoded by color alone.
- [ ] No clipped actions or horizontal page overflow on supported widths/zoom; card and navigation stay recognizable.
- [ ] Live updates do not steal focus, erase search or announce every packet; errors name a useful next step.

## Verification

Run automated semantic/contrast checks where supported and manual keyboard/screen-reader/touch tasks on actual builds. Keep screenshots and interaction results with versions; do not call this full conformance without the corresponding scope.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Update the UI acceptance/accessibility evidence and component guidance with intentional departures from tiny/low-contrast legacy typography.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not preserve an inaccessible rule merely because it appears in the source CSS, or replace native controls with a custom interaction framework.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
