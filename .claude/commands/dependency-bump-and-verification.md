---
name: dependency-bump-and-verification
description: Workflow command scaffold for dependency-bump-and-verification in koi.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /dependency-bump-and-verification

Use this workflow when working on **dependency-bump-and-verification** in `koi`.

## Goal

Update one or more dependencies to a newer version, update Cargo.lock and Cargo.toml as needed, verify the code compiles and passes lints/tests, and update documentation references if necessary.

## Common Files

- `Cargo.toml`
- `Cargo.lock`
- `crates/*/Cargo.toml`
- `.agentic/reference/utilities.md`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Update version(s) in Cargo.toml for affected crate(s).
- Run cargo update to refresh Cargo.lock.
- Verify the code compiles (cargo build --all-targets).
- Run lints (clippy -D warnings).
- Run tests for affected crates.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.