```markdown
# koi Development Patterns

> Auto-generated skill from repository analysis

## Overview

This skill teaches you the core development patterns, coding conventions, and collaborative workflows used in the `koi` Rust codebase. You'll learn how to structure code, manage dependencies, contribute major features, maintain documentation ledgers, and follow the team's workflow automation using suggested commands.

## Coding Conventions

### File Naming

- **CamelCase** is used for file names, e.g.:
  - `myModule.rs`
  - `userProfile.rs`

### Imports

- **Relative imports** are preferred:
  ```rust
  mod utils;
  use crate::utils::parse_config;
  ```

### Exports

- **Named exports** are used:
  ```rust
  pub fn do_something() { ... }
  pub struct MyStruct { ... }
  ```

### Commit Messages

- **Conventional commit** style:
  - Prefixes: `docs`, `build`, `feat`
  - Example: `feat: add async support to network module`

## Workflows

### Dependency Bump and Verification

**Trigger:** When you need to update dependencies or respond to Dependabot PRs  
**Command:** `/bump-dep`

1. Update version(s) in `Cargo.toml` for affected crate(s).
2. Run `cargo update` to refresh `Cargo.lock`.
3. Verify the code compiles:
   ```sh
   cargo build --all-targets
   ```
4. Run lints:
   ```sh
   cargo clippy -- -D warnings
   ```
5. Run tests for affected crates:
   ```sh
   cargo test
   ```
6. Update documentation references to dependency versions if needed (e.g., `.agentic/reference/utilities.md`).

**Files involved:**  
`Cargo.toml`, `Cargo.lock`, `crates/*/Cargo.toml`, `.agentic/reference/utilities.md`

---

### Epic Feature Development with Plan and Ledger

**Trigger:** When implementing a major feature or refactor (epic)  
**Command:** `/start-epic`

1. Write or update a plan/acceptance doc in `docs/prompts/plans/` (include goal, file list, tests, risks).
2. Implement or refactor code across multiple files/crates.
3. Update or add documentation (e.g., `README.md`, guides, API docs).
4. Update the progress/acceptance ledger (`docs/prompts/PROGRESS.md`).
5. Update reference docs if APIs or utilities change.
6. Add or update tests for new/refactored code.
7. Cross-link in `.agentic/CONTEXT.md` or similar context files.

**Files involved:**  
`docs/prompts/plans/*.md`, `docs/prompts/PROGRESS.md`, `crates/*/*.rs`, `crates/*/Cargo.toml`, `docs/guides/*.md`, `docs/reference/*.md`, `.agentic/CONTEXT.md`, `README.md`

---

### Documentation Ledger and CI Integration

**Trigger:** When adding or updating a documentation ledger and integrating it with CI  
**Command:** `/add-ledger`

1. Create or update a documentation ledger file (e.g., `docs/SURFACES.md`).
2. Add or update a CI job in `.github/workflows/ci.yml` to lint or validate the ledger.
3. Write or update a linting script in `scripts/` (e.g., `scripts/lint-ledger.sh`).
4. Cross-link the ledger from `.agentic/CONTEXT.md` or similar context files.

**Files involved:**  
`docs/SURFACES.md`, `.github/workflows/ci.yml`, `scripts/lint-*.sh`, `.agentic/CONTEXT.md`

---

## Testing Patterns

- **Test file pattern:** `*.test.*`
- **Framework:** Not explicitly specified, but typically Rust's built-in test framework is used.
- **Example:**
  ```rust
  #[cfg(test)]
  mod tests {
      use super::*;

      #[test]
      fn test_feature() {
          assert_eq!(my_function(), expected_value);
      }
  }
  ```

## Commands

| Command      | Purpose                                                     |
|--------------|-------------------------------------------------------------|
| /bump-dep    | Update dependencies, verify build, run lints and tests      |
| /start-epic  | Begin a major feature or refactor with planning and ledger  |
| /add-ledger  | Add or update a documentation ledger and CI integration     |
```