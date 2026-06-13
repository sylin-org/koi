---
name: epic-feature-development-with-plan-and-ledger
description: Workflow command scaffold for epic-feature-development-with-plan-and-ledger in koi.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /epic-feature-development-with-plan-and-ledger

Use this workflow when working on **epic-feature-development-with-plan-and-ledger** in `koi`.

## Goal

Develop a major feature or refactor (epic), including implementation, documentation, a plan/acceptance doc, and updating a progress ledger.

## Common Files

- `docs/prompts/plans/*.md`
- `docs/prompts/PROGRESS.md`
- `crates/*/*.rs`
- `crates/*/Cargo.toml`
- `docs/guides/*.md`
- `docs/reference/*.md`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Write or update a plan/acceptance doc in docs/prompts/plans/ (goal, file list, tests, risks).
- Implement or refactor code across multiple files/crates.
- Update or add documentation (README, guides, API docs).
- Update progress/acceptance ledger (docs/prompts/PROGRESS.md).
- Update reference docs if APIs or utilities change.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.