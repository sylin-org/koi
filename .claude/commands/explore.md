# Exploration Phase

Before implementing anything for this task, complete the following steps in order. Do not write any production code until all steps are done.

## Step 1: Understand the task

Restate the task in your own words. Identify:
- What crate does this touch? (`koi-common`, `koi-client`, `koi-mdns`, `koi-config`, `koi-dns`, `koi-health`, `koi-proxy`, `koi-certmesh`, `koi-crypto`, `koi-truststore`, `koi-embedded`, `koi` binary)
- Which layer is involved? (transport, business logic, wire format, CLI)
- What's the expected output? (new feature, refactor, bug fix, extension)

## Step 2: Read existing code

Open and read the **3-5 most relevant existing files**. Use these searches to find them:

```bash
# Find types related to the task
rg "struct|enum|trait" crates/ -l | head -20

# Find functions related to the task
rg "fn keyword_from_task" crates/

# Find the closest existing implementation to what we're building
rg "similar_feature_keyword" crates/ -l
```

For each file you read, state in one sentence what it does and whether it's relevant.

## Step 3: Check for existing constants & types

Run these searches explicitly and report the results:

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

State clearly: **"Already exists"** or **"Needs to be created"** for each piece of functionality the task requires.

## Step 4: Identify the closest pattern to follow

Find the most similar existing feature in the codebase. For example:
- New HTTP endpoint → read an existing handler in `crates/koi/src/adapters/http.rs` or `crates/koi/src/adapters/dispatch.rs`
- New CLI command → read an existing module in `crates/koi/src/commands/`
- New shared types → read `crates/koi-common/src/types.rs` or `crates/koi-common/src/api.rs`
- New domain logic → read the relevant domain crate (e.g., `crates/koi-mdns/`, `crates/koi-dns/`)
- Platform integration → read `crates/koi/src/platform/`
- Formatting → read `crates/koi/src/format.rs`
- Client operations → read `crates/koi-client/src/lib.rs`

State: **"Following the pattern from [specific file]"**

## Step 5: Plan where new code will live

For every new file, type, function, or constant, state its location and justify it:

| New code | Location | Justification |
|----------|----------|---------------|
| (type/fn/const) | (exact path) | (why here and not elsewhere) |

Apply the crate placement rules:
- Shared types, traits, utilities? → `crates/koi-common/`
- mDNS protocol types? → `crates/koi-mdns/`
- HTTP client methods? → `crates/koi-client/`
- CLI commands / subcommands? → `crates/koi/src/commands/`
- HTTP server / adapters? → `crates/koi/src/adapters/`
- OS integration? → `crates/koi/src/platform/`
- Output formatting? → `crates/koi/src/format.rs`
- DNS domain logic? → `crates/koi-dns/`
- Health checks? → `crates/koi-health/`
- Reverse proxy? → `crates/koi-proxy/`
- Certificate mesh? → `crates/koi-certmesh/`
- Crypto primitives? → `crates/koi-crypto/`
- Configuration / breadcrumb? → `crates/koi-config/`

## Step 6: Check for potential violations

Before proceeding, confirm:

- [ ] No mdns-sd imports outside `crates/koi-mdns/`
- [ ] No new type duplicates one in `koi-common` or domain crates
- [ ] Constants are co-located with usage (not in a centralized module)
- [ ] New protocol types have serde round-trip tests planned
- [ ] Cross-crate dependencies flow downward (binary → domain crates → koi-common)

## Step 7: Present the plan

Summarize your findings in this format:

**Task:** (one sentence)
**Files read:** (list with one-sentence relevance notes)
**Reusing:** (list what already exists)
**Creating new:** (table from Step 5)
**Pattern:** (which existing file you're following)
**Risks:** (anything you're unsure about)

**Then stop and wait for approval before implementing.**
