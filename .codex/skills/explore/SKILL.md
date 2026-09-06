---
name: explore
description: Explore relevant ownership, existing patterns and risks before changing Koi code or CI. Keep exploration proportional to the change; use existing evidence instead of repeating unrelated repository-wide scans.
---

# Explore

Before changing code, identify its owner, closest existing pattern and meaningful
failure cases. Keep exploration proportional: a local UI fix does not require
scanning every domain crate, and a CI change does not require a Rust-type inventory.
Reuse recently inspected, unchanged evidence instead of repeating the same reads.

## Relevant exploration

- Inspect worktree state and read the affected implementation and nearby tests.
- Search for the specific types, constants and utilities needed by this change
  before introducing replacements. Expand the search only when ownership is unclear.
- For a new boundary, consult `docs/reference/architecture.md` and the relevant
  ADR or contract. Resolve moved files with `rg`; do not recreate a stale path.
- Record intended behavior, exact files, reused pattern and risk-based checks
  briefly in commentary or the existing task report. No fixed file count, table,
  seven-step transcript or separate claim commit is required for solo source work.
- Prefer a usable vertical slice. Add infrastructure only for a concrete dependency
  or safety requirement of that slice.

## Koi ownership guardrails

Shared vocabulary belongs in `koi-common`; state belongs in its existing domain;
`koi-compose` owns cross-domain composition; `koi-serve` owns serving;
`koi-client` owns the HTTP client; the binary owns CLI and native installation;
`koi-ui` owns pure presentation; sibling `koi-desktop` owns the native webview
and browser opening.

Preserve downward dependencies, wire compatibility, provider boundaries and
co-located constants. Keep `mdns-sd` imports inside `koi-mdns`. Plan meaningful
compatibility and round-trip tests for new protocol types, without imposing that
ritual on ordinary DOM or CI changes.

## Proceed and verify

For an already authorized task, share the short plan and implement without a
routine second approval pause. Ask only when a material scope, authority or
tradeoff decision is missing. Exploration does not grant additional authority
for external actions.

Use the charter's proportional verification policy: focused local checks,
broad CI at product milestones, targeted native verification, and complete
candidate/release evidence. Test behavior and meaningful failure cases, not
source spelling or incidental CSS constants.
