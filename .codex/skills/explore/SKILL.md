---
name: explore
description: Run a mandatory pre-implementation exploration workflow before writing production code. Use when a task requires code changes and Codex must first map concerns/layers, read relevant files, check existing constants and types, identify the closest existing pattern, plan exact code placement, and confirm architectural guardrails.
---

# Explore

Before implementing anything for a task, complete the following steps in order.
Do not write production code until all steps are done.

## Step 1: Understand the task

Restate the task in your own words. Identify:
- What crate this touches: `koi-common`, `koi-client`, `koi-mdns`, `koi-config`, `koi-dns`, `koi-health`, `koi-proxy`, `koi-certmesh`, `koi-crypto`, `koi-truststore`, `koi-embedded`, `koi` binary
- Which layer is involved: transport, business logic, wire format, CLI
- Expected output: new feature, refactor, bug fix, extension

## Step 2: Read existing code

Open and read the 3-5 most relevant existing files.
Use searches like:

```bash
# Find types related to the task
rg "struct|enum|trait" crates/ -l | head -20

# Find functions related to the task
rg "fn keyword_from_task" crates/

# Find the closest existing implementation to what we're building
rg "similar_feature_keyword" crates/ -l
```

For each file read, state in one sentence what it does and whether it is relevant.

## Step 3: Check for existing constants and types

Run these searches explicitly and report results:

```bash
# Constants in the binary crate
rg "const " crates/koi/src/

# Shared types and utilities
rg "struct|enum" crates/koi-common/src/
rg "struct|enum" crates/koi-mdns/src/protocol/

# Client types
rg "struct|enum" crates/koi-client/src/

# Domain crate types
rg "struct|enum" crates/koi-dns/src/
rg "struct|enum" crates/koi-health/src/
rg "struct|enum" crates/koi-proxy/src/
rg "struct|enum" crates/koi-certmesh/src/
```

For each required piece of functionality, state clearly:
- `Already exists`
- `Needs to be created`

## Step 4: Identify the closest pattern to follow

Find the most similar existing feature in the codebase.
Examples:
- New HTTP endpoint: read `crates/koi/src/adapters/http.rs` or `crates/koi/src/adapters/dispatch.rs`
- New CLI command: read a module in `crates/koi/src/commands/`
- New shared types: read `crates/koi-common/src/types.rs` or `crates/koi-common/src/api.rs`
- New domain logic: read the relevant domain crate (e.g., `crates/koi-mdns/`, `crates/koi-dns/`)
- Platform integration: read `crates/koi/src/platform/`
- Formatting: read `crates/koi/src/format.rs`
- Client operations: read `crates/koi-client/src/lib.rs`

State:
- `Following the pattern from [specific file]`

## Step 5: Plan where new code will live

For every new file, type, function, or constant, state location and justification:

| New code | Location | Justification |
|----------|----------|---------------|
| (type/fn/const) | (exact path) | (why here and not elsewhere) |

Apply crate placement rules:
- Shared types, traits, utilities: `crates/koi-common/`
- mDNS protocol types: `crates/koi-mdns/`
- HTTP client methods: `crates/koi-client/`
- CLI commands / subcommands: `crates/koi/src/commands/`
- HTTP server / adapters: `crates/koi/src/adapters/`
- OS integration: `crates/koi/src/platform/`
- Output formatting: `crates/koi/src/format.rs`
- DNS domain logic: `crates/koi-dns/`
- Health checks: `crates/koi-health/`
- Reverse proxy: `crates/koi-proxy/`
- Certificate mesh: `crates/koi-certmesh/`
- Crypto primitives: `crates/koi-crypto/`
- Configuration / breadcrumb: `crates/koi-config/`

## Step 6: Check for potential violations

Before proceeding, confirm:

- [ ] No `mdns-sd` imports outside `crates/koi-mdns/`
- [ ] No new type duplicates one in `koi-common` or domain crates
- [ ] Constants are co-located with usage (not in a centralized module)
- [ ] New protocol types have serde round-trip tests planned
- [ ] Cross-crate dependencies flow downward (binary -> domain crates -> koi-common)

## Step 7: Present the plan

Summarize findings in this exact format:

**Task:** (one sentence)
**Files read:** (list with one-sentence relevance notes)
**Reusing:** (list what already exists)
**Creating new:** (table from Step 5)
**Pattern:** (which existing file you're following)
**Risks:** (anything you're unsure about)

Then stop and wait for approval before implementing.
