---
name: dependency-update-and-security-audit
description: Workflow command scaffold for dependency-update-and-security-audit in koi.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /dependency-update-and-security-audit

Use this workflow when working on **dependency-update-and-security-audit** in `koi`.

## Goal

Update dependencies to address security advisories, remove or replace vulnerable/unmaintained crates, and ensure the codebase passes security audits and CI.

## Common Files

- `Cargo.toml`
- `Cargo.lock`
- `.github/workflows/ci.yml`
- `crates/*/Cargo.toml`
- `crates/*/src/**/*.rs`
- `docs/assessment/*.md`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Run cargo audit to identify vulnerabilities and unmaintained dependencies.
- Update Cargo.toml and/or Cargo.lock to bump or remove affected dependencies.
- Refactor code to migrate away from deprecated or unmaintained crates (if necessary).
- Update CI configuration to reflect new audit status (e.g., remove/add ignores).
- Add documentation or assessment notes if a significant dependency change is made.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.