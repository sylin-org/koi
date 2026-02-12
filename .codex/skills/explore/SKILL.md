---
name: explore
description: Run a mandatory pre-implementation exploration workflow before writing production code. Use when a task requires code changes and Codex must first map concerns/layers, read relevant files, check existing constants and types, identify the closest existing pattern, plan exact code placement, and confirm architectural guardrails.
---

# Explore

Before implementing anything for a task, complete the following steps in order.
Do not write production code until all steps are done.

## Step 1: Understand the task

Restate the task in your own words. Identify:
- What concern this touches: adapters, core, protocol, commands, platform, config
- Which layer is involved: transport, business logic, wire format, CLI
- Expected output: new feature, refactor, bug fix, extension

## Step 2: Read existing code

Open and read the 3-5 most relevant existing files.
Use searches like:

```bash
# Find types related to the task
rg "struct|enum|trait" src/ -l | head -20

# Find functions related to the task
rg "fn keyword_from_task" src/

# Find the closest existing implementation to what we're building
rg "similar_feature_keyword" src/ -l
```

For each file read, state in one sentence what it does and whether it is relevant.

## Step 3: Check for existing constants and types

Run these searches explicitly and report results:

```bash
# Constants that might already exist
rg "const " src/core/mod.rs
rg "const " src/adapters/
rg "const " src/main.rs
rg "const " src/config.rs

# Protocol types that might already exist
rg "struct|enum" src/protocol/mod.rs
rg "struct|enum" src/protocol/request.rs
rg "struct|enum" src/protocol/response.rs

# Core types that might already exist
rg "struct|enum" src/core/mod.rs
rg "struct|enum" src/core/registry.rs
```

Also check `.agentic/reference/utilities.md` for the full constants and types catalog.

For each required piece of functionality, state clearly:
- `Already exists`
- `Needs to be created`

## Step 4: Identify the closest pattern to follow

Find the most similar existing feature in the codebase.
Examples:
- New HTTP endpoint: read `src/adapters/http.rs`
- New CLI command: read `src/commands/standalone.rs` or `src/commands/client.rs`
- New protocol type: read `src/protocol/mod.rs`
- New core operation: read `src/core/mod.rs`
- New admin command: read `src/admin.rs`
- Platform integration: read `src/platform/`

State:
- `Following the pattern from [specific file]`

## Step 5: Plan where new code will live

For every new file, type, function, or constant, state location and justification:

| New code | Location | Justification |
|----------|----------|---------------|
| (type/fn/const) | (exact path) | (why here and not elsewhere) |

Apply layer placement rules:
- Wire format types: `src/protocol/`
- Business logic: `src/core/`
- Transport handling: `src/adapters/`
- CLI command: `src/commands/`
- OS integration: `src/platform/`
- Formatting: `src/format.rs`

## Step 6: Check for potential violations

Before proceeding, confirm:

- [ ] No `mdns-sd` imports outside `core/daemon.rs`
- [ ] No new constant duplicates one in `.agentic/reference/utilities.md`
- [ ] No new type duplicates one in `protocol/` or `core/`
- [ ] Constants are co-located with usage (not in a centralized module)
- [ ] New protocol types have serde round-trip tests planned

## Step 7: Present the plan

Summarize findings in this exact format:

**Task:** (one sentence)
**Files read:** (list with one-sentence relevance notes)
**Reusing:** (list what already exists)
**Creating new:** (table from Step 5)
**Pattern:** (which existing file you're following)
**Risks:** (anything you're unsure about)

Then stop and wait for approval before implementing.
