# R07 - Build Home as the service launchpad

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **A user opens Koi, recognizes a service, and uses it without learning DNS-SD.**

- Dependencies: [R05](R05-catalog-api-and-preferences.md), [R06](R06-rust-ui-and-family-foundation.md)
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
4. Write the bounded plan in reports/R07.md (or reports/R07-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Starting source

- `docs/assessment/2026-09-delight-mandates-and-ux-direction.md`
- `../koi-desktop/ui/app.js`
- `../koi-desktop/ui/sentences.js`
- `crates/koi-dashboard/assets/mdns-browser.html`
- `crates/koi-dashboard/assets/dashboard.html`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Use the R06 component map and real R05 catalog. Implement Home with search, favorites, available services and a bounded attention area. Use the source family rows and meaningful direct actions.

2. Search friendly name, user alias, host, address and category; preserve selection and stable ordering during updates. Offer clear-filter, no discoveries, discovery unavailable, reconnecting/stale and absent-favorite states distinctly.

3. Use real inspectable HTTP(S) destinations with safe scheme handling and the desktop's native external opening path where applicable. Escape hostile network names/TXT data; API-only services use connection details. Confirm endpoint protocol evidence before showing Open.

4. Provide service details alongside the list on wide layouts and a focused detail route on narrow layouts. Show check location/time, endpoint, sources and technical details. Integrate only completed backend actions; future sharing/HTTPS buttons appear when their later tasks land.

## Acceptance cases

- [ ] The forgotten Notes app is found by device/category and opens its actual target with one primary action.
- [ ] No-match search says no matches and clears correctly while discovery remains healthy.
- [ ] A stopped favorite persists; an interrupted feed shows freshness and recovers automatically without a Refresh ritual.
- [ ] A malicious name renders as text; javascript/file/custom schemes cannot become unreviewed Open links; an API is not presented as a web dashboard.

## Verification

Exercise live catalog search/open/details via keyboard and pointer at desktop and 320 px widths. Add meaningful interaction tests for search state, hostile data, reconnect and link safety; screenshots alone are insufficient.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Add a Home usage page or update getting-started with the actual controls and observed limits. Record R07 component entry points.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not reintroduce Browser/Discover as competing landing pages, put raw record counts above actions, or wire production controls to preview toasts.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
