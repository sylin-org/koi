---
name: documentation-ledger-and-ci-integration
description: Workflow command scaffold for documentation-ledger-and-ci-integration in koi.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /documentation-ledger-and-ci-integration

Use this workflow when working on **documentation-ledger-and-ci-integration** in `koi`.

## Goal

Add or update a documentation ledger (such as a surface ledger), integrate it into CI for linting, and cross-link from context or reference files.

## Common Files

- `docs/SURFACES.md`
- `.github/workflows/ci.yml`
- `scripts/lint-*.sh`
- `.agentic/CONTEXT.md`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Create or update a documentation ledger file (e.g., docs/SURFACES.md).
- Add or update a CI job in .github/workflows/ci.yml to lint or validate the ledger.
- Write or update a linting script in scripts/.
- Cross-link the ledger from .agentic/CONTEXT.md or similar context files.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.