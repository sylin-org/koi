# R06 - Choose and build the Rust UI foundation with Sylin assets

You are executing one work order in Koi Epic 003. You need no prior conversation.
Deliver this result: **A measured Rust-based rendering choice serves one shared UI with Koi's existing family language.**

- Dependencies: [R01](R01-contract-and-handover.md), [R05](R05-catalog-api-and-preferences.md)
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
4. Write the bounded plan in reports/R06.md (or reports/R06-<slice>.md), then
   execute without another routine plan-approval question. Use the charter's report format.

## Choose one slice

This task has separately tracked slices: `renderer-decision`, `shared-shell`.
Select one applicable dependency-ready slice from LEDGER.md. Execute and report only
that slice; complete the parent task only when all required rows are accepted.
The slice table defines order, owner and narrow deliverable.

## Starting source

- `../koi-desktop/Cargo.toml`
- `../koi-desktop/src/main.rs`
- `../koi-desktop/src/local_daemon.rs`
- `../koi-desktop/ui/styles.css`
- `../koi-desktop/ui/index.html`
- `crates/koi-dashboard/src/lib.rs`
- `crates/koi-serve/src/pond_ui.rs`
- `docs/assessment/2026-09-sylin-visual-dictionary.md`
- `docs/adr/033-koi-desktop-workbench.md`

Paths are relative to Koi root; ../koi-desktop is the sibling. Search moved paths
with rg, update the contract map, and inspect the current owner before creating files.

## Work

1. Timebox a vertical spike to one live catalog row plus navigation and the original mascot card. Compare retaining the Rust/Tauri shell with a Rust-authored shared web view against one viable Rust desktop/web alternative. Consult current official framework documentation, record build size/runtime dependencies and supported target evidence, then choose one in an ADR. No aesthetic framework preference counts as portability evidence.

2. Prove the selected route for Windows, glibc Linux, musl desktop where claimed, and headless web. Keep native tray/window/authenticated control boundaries. Record unavailable physical targets as pending and require a proven fallback before selecting an incompatible renderer.

3. Extract a versioned family base from the actual Koi CSS and verify provenance against Ghostlight at browser-mcp/crates/orchestrator/ui/styles.css if that sibling exists. Keep the blue accent, shared text/surface/motion tokens and original koi.png. Do not introduce a runtime dependency on another checkout or CDN.

4. Land the minimal reusable shell and real data adapter, top Home/Devices/Settings/About navigation, error/loading states and component examples. Write a component/source map for the next executors. Spike-only variants must be retired once the decision is made.

## Acceptance cases

- [ ] One live catalog row and the original card render through the selected route; a screenshot mock is not the spike result.
- [ ] Desktop and headless build paths are reproducible from locked sources; platform limitations are explicit.
- [ ] Top navigation reflows at 320 px; keyboard focus and reduced motion are visible; critical text remains readable.
- [ ] A packaged build loads its own assets offline and discovers the authenticated service without a second daemon.

## Verification

Run selected Rust/UI build and component smoke checks, existing desktop tests during transition, and visual/native smoke evidence for available targets. Record metrics and pending OS validation in the ADR, never fill missing measurements with estimates.

For code changes, finish the applicable CHARTER.md gates. Record missing native or
hosted prerequisites explicitly; a source-only check cannot close that acceptance.

## Documentation and handoff

Record the renderer/asset ownership decision in CONTRACT.md and the ADR. Add a short component map that names the exact files for Home, device details, settings, state badges and card.

Update the selected LEDGER.md row and its report with exact source changes, commands,
results, remaining work and the next concrete action. Cite owned fleet evidence for
native claims. Retest downstream contracts affected by your change.

## Scope boundary

Do not implement all screens in this spike, adopt a JS-owned product state model, redraw the mascot, or change Ghostlight production code. Browser-delivered CSS and minimal generated interactivity are allowed; Rust owns application and platform behavior.

A standalone invocation ends after this work order. A fleet invocation returns to
fleet/task.md after publishing the slice and rechecks the assigned dependencies.
If this slice is too large, checkpoint coherent work and its exact next step.
Do not mark acceptance complete with pending required evidence or production placeholders.
Test fixtures prove only their stated layer; they cannot replace native or user evidence.
